// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/kem"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"sync/atomic"
	"time"
)

type clientHandshakeStateTLS13 struct {
	c           *Conn
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	helloInner  *clientHelloMsg
	helloBase   *clientHelloMsg
	keyshares   []clientKeysharePrivate

	session     *ClientSessionState
	earlySecret []byte
	binderKey   []byte

	certReq         *certificateRequestMsgTLS13
	usingPSK        bool
	sentDummyCCS    bool
	suite           *cipherSuiteTLS13
	transcript      hash.Hash
	transcriptInner hash.Hash
	handshakeSecret []byte
	masterSecret    []byte
	trafficSecret   []byte // client_application_traffic_secret_0
}

// processDelegatedCredentialFromServer unmarshals the DelegatedCredential
// offered by the server (if present) and validates it using the peer
// certificate.
func (hs *clientHandshakeStateTLS13) processDelegatedCredentialFromServer(dc []byte, certVerifyMsg *certificateVerifyMsg) error {
	c := hs.c

	var dCred *DelegatedCredential
	var err error
	if dc != nil {
		// Assert that the DC extension was indicated by the client.
		if !hs.hello.delegatedCredentialSupported {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: got delegated credential extension without indication")
		}

		dCred, err = unmarshalDelegatedCredential(dc)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return fmt.Errorf("tls: delegated credential: %s", err)
		}

		if !isSupportedSignatureAlgorithm(dCred.cred.expCertVerfAlgo, supportedSignatureAlgorithmsDC) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: delegated credential used with invalid signature algorithm")
		}
	}

	if dCred != nil {
		if !dCred.Validate(c.peerCertificates[0], DCServer, c.config.time(), certVerifyMsg) {
			return errors.New("tls: invalid delegated credential")
		}
	}

	c.verifiedDC = dCred

	return nil
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.ecdheParams, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if numshares := len(hs.keyshares); numshares == 0 || len(hs.hello.keyShares) != numshares {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()
	hs.transcript.Write(hs.hello.marshal())

	// When offering ECH, it is not known whether ECH was accepted until the
	// ServerHello is processed. In particular, we do not know at this point if
	// the server used the ClientHelloOuter or the ClientHelloInner.
	if c.ech.offered {
		hs.transcriptInner = hs.suite.hash.New()
		hs.transcriptInner.Write(hs.helloInner.marshal())
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	// Determine if ECH was accepted.
	if hs.c.ech.offered {
		secret := hs.suite.extract(hs.helloInner.random, nil)
		context := hs.serverHello.random[:24]
		acceptConfirmation := hs.suite.expandLabel(secret, echTls13LabelAcceptConfirm, context, 8)
		if bytes.Equal(hs.serverHello.random[24:], acceptConfirmation) {
			c.ech.accepted = true
			hs.hello = hs.helloInner
			hs.transcript = hs.transcriptInner
		}
	}

	// Resolve the server name now that ECH acceptance has been determined.
	//
	// NOTE(cjpatton): Currently the client sends the same ALPN extension in the
	// ClientHelloInner and ClientHelloOuter. If that changes, then we'll need
	// to resolve ALPN here as well.
	c.serverName = hs.hello.serverName

	hs.transcript.Write(hs.serverHello.marshal())

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	// Branch off to KEMTLS land
	if c.verifiedDC != nil && c.verifiedDC.cred.expCertVerfAlgo.isKEMTLS() {
		return hs.handshakeKEMTLS()
	}
	if err := hs.readServerCertificateVerify(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if err := hs.abortIfRequired(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c
	c.hrrTriggered = true

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	hs.transcript.Write(hs.serverHello.marshal())

	if c.ech.offered {
		chHash = hs.transcriptInner.Sum(nil)
		hs.transcriptInner.Reset()
		hs.transcriptInner.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.transcriptInner.Write(chHash)
		hs.transcriptInner.Write(hs.serverHello.marshal())
	}

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hs.helloBase.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		curveOK := false
		for _, id := range hs.helloBase.supportedCurves {
			if id == curveID {
				curveOK = true
				break
			}
		}
		if !curveOK {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if curveID.isKem() {
			kemID := kem.KemID(curveID)
			pk, sk, err := kem.Keypair(c.config.rand(), kemID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyshares = []clientKeysharePrivate{sk}
			hs.hello.keyShares = []keyShare{{group: CurveID(pk.Id), data: pk.PublicKey}}
		} else {
			if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
				c.sendAlert(alertInternalError)
				return errors.New("tls: CurvePreferences includes unsupported curve")
			}
			params, err := generateECDHEParameters(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyshares = []clientKeysharePrivate{params}
			hs.hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}

		}
	}

	hs.helloBase.raw = nil
	if len(hs.helloBase.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := uint32(c.config.time().Sub(hs.session.receivedAt) / time.Millisecond)
			hs.helloBase.pskIdentities[0].obfuscatedTicketAge = ticketAge + hs.session.ageAdd

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			transcript.Write(hs.serverHello.marshal())
			transcript.Write(hs.helloBase.marshalWithoutBinders())
			pskBinders := [][]byte{hs.suite.finishedHash(hs.binderKey, transcript)}
			hs.helloBase.updateBinders(pskBinders)
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hs.helloBase.pskIdentities = nil
			hs.helloBase.pskBinders = nil
		}
	}

	var err error
	hs.hello, hs.helloInner, err = c.echOfferOrGrease(hs.helloBase)
	if err != nil {
		return err
	}

	if testingECHIllegalHandleAfterHRR {
		// Triggers a server abort, since this changes the cipher suite offered
		// by the client.
		hs.hello.encryptedClientHello[0] ^= 0xff
	}

	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript.Write(hs.hello.marshal())
	if c.ech.offered {
		hs.transcriptInner.Write(hs.helloInner.marshal())
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}

	foundGroup := false
	for _, keyShare := range hs.keyshares {
		if ecdheParams, ok := keyShare.(ecdheParameters); ok {
			if hs.serverHello.serverShare.group == ecdheParams.CurveID() {
				foundGroup = true
			}
		} else {
			kemShare := keyShare.(*kem.PrivateKey)
			if CurveID(kemShare.Id) == hs.serverHello.serverShare.group {
				foundGroup = true
			}
		}
	}
	if !foundGroup {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c
	var sharedKey []byte
	for _, keyShare := range hs.keyshares {
		if params, ok := keyShare.(ecdheParameters); ok && params.CurveID() == hs.serverHello.serverShare.group {
			sharedKey = params.SharedKey(hs.serverHello.serverShare.data)
		} else if kemPrivate, ok := keyShare.(*kem.PrivateKey); ok && kemPrivate.Id == kem.KemID(hs.serverHello.serverShare.group) {
			var err error
			sharedKey, err = kem.Decapsulate(kemPrivate, hs.serverHello.serverShare.data)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
		}
	}

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		earlySecret = hs.suite.extract(nil, nil)
	}
	hs.handshakeSecret = hs.suite.extract(sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	clientSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}
	hs.transcript.Write(encryptedExtensions.marshal())

	if len(encryptedExtensions.alpnProtocol) != 0 && len(hs.hello.alpnProtocols) == 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server advertised unrequested ALPN extension")
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	// If the server rejects ECH, then it may send retry configurations. If
	// present, we must check them for syntactic correctness and abort if they
	// are not correct.
	if c.ech.offered && len(encryptedExtensions.encryptedClientHello) > 0 {
		c.ech.retryConfigs = encryptedExtensions.encryptedClientHello
		if _, err = UnmarshalECHConfigs(c.ech.retryConfigs); err != nil {
			c.sendAlert(alertIllegalParameter)
			return fmt.Errorf("tls: ech: failed to parse retry configs: %s", err)
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.transcript.Write(certReq.marshal())

		hs.certReq = certReq

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	if len(certMsg.certificate.Certificate) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}
	hs.transcript.Write(certMsg.marshal())

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	if certMsg.delegatedCredential {
		if err := hs.processDelegatedCredentialFromServer(certMsg.certificate.DelegatedCredential, certVerify); err != nil {
			return err
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificateVerify() error {
	if hs.usingPSK {
		return nil
	}
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	pk := c.peerCertificates[0].PublicKey
	if c.verifiedDC != nil {
		pk = c.verifiedDC.cred.publicKey
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, pk,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	hs.transcript.Write(certVerify.marshal())

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	hs.transcript.Write(finished.marshal())

	// Derive secrets that take context through the server Finished.

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

func certificateRequestInfo(certReq *certificateRequestMsgTLS13) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		SupportsDelegatedCredential: certReq.supportDelegatedCredential,
		SignatureSchemes:            certReq.supportedSignatureAlgorithms,
		SignatureSchemesDC:          certReq.supportedSignatureAlgorithmsDC,
		AcceptableCAs:               certReq.certificateAuthorities,
	}

	return cri
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:               hs.certReq.certificateAuthorities,
		SignatureSchemes:            hs.certReq.supportedSignatureAlgorithms,
		SupportsDelegatedCredential: hs.certReq.supportDelegatedCredential,
		SignatureSchemesDC:          hs.certReq.supportedSignatureAlgorithmsDC,
		Version:                     c.vers,
	})
	if err != nil {
		return err
	}

	if hs.certReq.supportDelegatedCredential && c.config.GetDelegatedCredential != nil {
		dCred, priv, err := c.config.GetDelegatedCredential(nil, certificateRequestInfo(hs.certReq))
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil
		}

		if dCred != nil && priv != nil {
			cert.PrivateKey = priv
			if dCred.raw == nil {
				dCred.raw, err = dCred.marshal()
				if err != nil {
					c.sendAlert(alertInternalError)
					return err
				}
			}
			cert.DelegatedCredential = dCred.raw
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
	certMsg.delegatedCredential = hs.certReq.supportDelegatedCredential && len(cert.DelegatedCredential) > 0

	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	suppSigAlgo := hs.certReq.supportedSignatureAlgorithms
	if certMsg.delegatedCredential {
		suppSigAlgo = hs.certReq.supportedSignatureAlgorithmsDC
	}

	sigAlgorithm, err := selectSignatureScheme(c.vers, cert, suppSigAlgo)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	certVerifyMsg.signatureAlgorithm = sigAlgorithm

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	hs.transcript.Write(certVerifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certVerifyMsg.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	hs.transcript.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil && !c.config.ECHEnabled {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
	}

	return nil
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil || c.config.ECHEnabled {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	// Save the resumption_master_secret and nonce instead of deriving the PSK
	// to do the least amount of work on NewSessionTicket messages before we
	// know if the ticket will be used. Forward secrecy of resumed connections
	// is guaranteed by the requirement for pskModeDHE.
	session := &ClientSessionState{
		sessionTicket:      msg.label,
		vers:               c.vers,
		cipherSuite:        c.cipherSuite,
		masterSecret:       c.resumptionSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		nonce:              msg.nonce,
		useBy:              c.config.time().Add(lifetime),
		ageAdd:             msg.ageAdd,
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	c.config.ClientSessionCache.Put(cacheKey, session)

	return nil
}

func (hs *clientHandshakeStateTLS13) abortIfRequired() error {
	c := hs.c
	if c.ech.offered && !c.ech.accepted {
		// If ECH was rejected, then abort the handshake.
		c.sendAlert(alertECHRequired)
		return errors.New("tls: ech: rejected")
	}
	return nil
}
