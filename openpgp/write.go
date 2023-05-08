// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"crypto"
	"hash"
	"io"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/internal/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// DetachSign signs message with the private key from signer (which must
// already have been decrypted) and writes the signature to w.
// If config is nil, sensible defaults will be used.
func DetachSign(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return detachSign(w, signer, message, packet.SigTypeBinary, config)
}

// ArmoredDetachSign signs message with the private key from signer (which
// must already have been decrypted) and writes an armored signature to w.
// If config is nil, sensible defaults will be used.
func ArmoredDetachSign(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) (err error) {
	return armoredDetachSign(w, signer, message, packet.SigTypeBinary, config)
}

// DetachSignText signs message (after canonicalising the line endings) with
// the private key from signer (which must already have been decrypted) and
// writes the signature to w.
// If config is nil, sensible defaults will be used.
func DetachSignText(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return detachSign(w, signer, message, packet.SigTypeText, config)
}

// ArmoredDetachSignText signs message (after canonicalising the line endings)
// with the private key from signer (which must already have been decrypted)
// and writes an armored signature to w.
// If config is nil, sensible defaults will be used.
func ArmoredDetachSignText(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return armoredDetachSign(w, signer, message, packet.SigTypeText, config)
}

// DetachSignWriter signs a message with the private key from a signer (which must
// already have been decrypted) and writes the signature to w.
// DetachSignWriter returns a WriteCloser to which the message can be written to.
// The resulting WriteCloser must be closed after the contents of the message have
// been written. If utf8Message is set to true, the line endings of the message are
// canonicalised and the type of the signature will be SigTypeText.
// If config is nil, sensible defaults will be used.
func DetachSignWriter(w io.Writer, signer *Entity, utf8Message bool, config *packet.Config) (io.WriteCloser, error) {
	sigType := packet.SigTypeBinary
	if utf8Message {
		sigType = packet.SigTypeText
	}
	return detachSignWithWriter(w, signer, sigType, config)
}

func armoredDetachSign(w io.Writer, signer *Entity, message io.Reader, sigType packet.SignatureType, config *packet.Config) (err error) {
	out, err := armor.Encode(w, SignatureType, nil)
	if err != nil {
		return
	}
	err = detachSign(out, signer, message, sigType, config)
	if err != nil {
		return
	}
	return out.Close()
}

func detachSign(w io.Writer, signer *Entity, message io.Reader, sigType packet.SignatureType, config *packet.Config) (err error) {
	ptWriter, err := detachSignWithWriter(w, signer, sigType, config)
	if err != nil {
		return
	}
	_, err = io.Copy(ptWriter, message)
	if err != nil {
		return
	}
	return ptWriter.Close()
}

type detachSignWriter struct {
	signatureWriter io.Writer
	wrappedHasher   hash.Hash
	hasher          hash.Hash
	signer          *packet.PrivateKey
	sig             *packet.Signature
	config          *packet.Config
}

func (s detachSignWriter) Write(data []byte) (int, error) {
	return s.wrappedHasher.Write(data)
}

func (s detachSignWriter) Close() error {
	err := s.sig.Sign(s.hasher, s.signer, s.config)
	if err != nil {
		return err
	}
	return s.sig.Serialize(s.signatureWriter)
}

func detachSignWithWriter(w io.Writer, signer *Entity, sigType packet.SignatureType, config *packet.Config) (ptWriter io.WriteCloser, err error) {
	signingKey, ok := signer.SigningKeyById(config.Now(), config.SigningKey())
	if !ok {
		return nil, errors.InvalidArgumentError("no valid signing keys")
	}
	if signingKey.PrivateKey == nil {
		return nil, errors.InvalidArgumentError("signing key doesn't have a private key")
	}
	if signingKey.PrivateKey.Encrypted {
		return nil, errors.InvalidArgumentError("signing key is encrypted")
	}
	if _, ok := algorithm.HashToHashId(config.Hash()); !ok {
		return nil, errors.InvalidArgumentError("invalid hash function")
	}

	sig := createSignaturePacket(signingKey.PublicKey, sigType, config)

	h, err := sig.PrepareSign(config)
	if err != nil {
		return
	}
	wrappedHash, err := wrapHashForSignature(h, sig.SigType)
	if err != nil {
		return
	}
	return &detachSignWriter{
		signatureWriter: w,
		hasher:          h,
		wrappedHasher:   wrappedHash,
		signer:          signingKey.PrivateKey,
		sig:             sig,
		config:          config,
	}, nil
}

// FileHints contains metadata about encrypted files. This metadata is, itself,
// encrypted.
type FileHints struct {
	// IsUTF8 can be set to hint that the contents are utf8 encoded data
	IsUTF8 bool
	// FileName hints at the name of the file that should be written. It's
	// truncated to 255 bytes if longer. It may be empty to suggest that the
	// file should not be written to disk. It may be equal to "_CONSOLE" to
	// suggest the data should not be written to disk.
	FileName string
	// ModTime contains the modification time of the file, or the zero time if not applicable.
	ModTime time.Time
}

type EncryptParams struct {
	// KeyWriter is a Writer to which the encrypted
	// session keys are written to.
	// If nil, DataWriter is used instead.
	KeyWriter io.Writer
	// Hints contains file metadata for the literal data packet.
	// If nil, default is used.
	Hints *FileHints
	// Signed contains the private keys to produce signatures with
	// If nil, no signatures are created
	Signed *Entity
	// TextSig indicates if signatures of type SigTypeText should be produced
	TextSig bool
	// SessionKey provides a session key to be used for encryption.
	// If nil, a one-time session key is generated
	SessionKey []byte
	// Config provides the config to be used.
	// If Config is nil, sensible defaults will be used.
	Config *packet.Config
}

// SymmetricallyEncrypt acts like gpg -c: it encrypts a file with a passphrase.
// The resulting WriteCloser must be closed after the contents of the file have
// been written.
// If config is nil, sensible defaults will be used.
func SymmetricallyEncrypt(ciphertext io.Writer, passphrase []byte, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return SymmetricallyEncryptWithParams(passphrase, ciphertext, &EncryptParams{
		Hints:  hints,
		Config: config,
	})
}

// SymmetricallyEncryptWithParams acts like SymmetricallyEncrypt: but provides more configuration options
// EncryptParams provides the optional parameters.
// The resulting WriteCloser must be closed after the contents of the file have been written.
func SymmetricallyEncryptWithParams(passphrase []byte, dataWriter io.Writer, params *EncryptParams) (plaintext io.WriteCloser, err error) {
	if params == nil {
		params = &EncryptParams{}
	}
	return symmetricallyEncrypt(passphrase, dataWriter, params)
}

func symmetricallyEncrypt(passphrase []byte, dataWriter io.Writer, params *EncryptParams) (plaintext io.WriteCloser, err error) {
	if params.KeyWriter == nil {
		params.KeyWriter = dataWriter
	}
	if params.Hints == nil {
		params.Hints = &FileHints{}
	}
	if params.SessionKey == nil {
		params.SessionKey, err = packet.SerializeSymmetricKeyEncrypted(params.KeyWriter, passphrase, params.Config)
		defer func() {
			// zero the session key after we are done
			for i, _ := range params.SessionKey {
				params.SessionKey[i] = 0
			}
			params.SessionKey = nil
		}()
	} else {
		err = packet.SerializeSymmetricKeyEncryptedReuseKey(params.KeyWriter, params.SessionKey, passphrase, params.Config)
	}
	if err != nil {
		return
	}
	config := params.Config
	candidateCompression := []uint8{uint8(config.Compression())}
	candidateHashes := []uint8{hashToHashId(config.Hash())}
	cipherSuite := packet.CipherSuite{
		Cipher: config.Cipher(),
		Mode:   config.AEAD().Mode(),
	}
	if params.Signed != nil {
		// Check what the preferred hashes are for the signing key
		candidateHashes = []uint8{
			hashToHashId(crypto.SHA256),
			hashToHashId(crypto.SHA384),
			hashToHashId(crypto.SHA512),
			hashToHashId(crypto.SHA3_256),
			hashToHashId(crypto.SHA3_512),
		}
		defaultHashes := candidateHashes[0:1]
		primarySelfSignature, _ := params.Signed.PrimarySelfSignature()
		if primarySelfSignature == nil {
			return nil, errors.InvalidArgumentError("signed entity has no self-signature")
		}
		preferredHashes := primarySelfSignature.PreferredHash
		if len(preferredHashes) == 0 {
			preferredHashes = defaultHashes
		}
		candidateHashes = intersectPreferences(candidateHashes, preferredHashes)
		if len(candidateHashes) == 0 {
			candidateHashes = []uint8{hashToHashId(crypto.SHA256)}
		}
	}
	return encryptDataAndSign(dataWriter, params, candidateHashes, candidateCompression, config.Cipher(), config.AEAD() != nil, cipherSuite, nil)
}

// intersectPreferences mutates and returns a prefix of a that contains only
// the values in the intersection of a and b. The order of a is preserved.
func intersectPreferences(a []uint8, b []uint8) (intersection []uint8) {
	var j int
	for _, v := range a {
		for _, v2 := range b {
			if v == v2 {
				a[j] = v
				j++
				break
			}
		}
	}

	return a[:j]
}

// intersectPreferences mutates and returns a prefix of a that contains only
// the values in the intersection of a and b. The order of a is preserved.
func intersectCipherSuites(a [][2]uint8, b [][2]uint8) (intersection [][2]uint8) {
	var j int
	for _, v := range a {
		for _, v2 := range b {
			if v[0] == v2[0] && v[1] == v2[1] {
				a[j] = v
				j++
				break
			}
		}
	}

	return a[:j]
}

func hashToHashId(h crypto.Hash) uint8 {
	v, ok := algorithm.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
}

// EncryptWithParams encrypts a message to a number of recipients and, optionally,
// signs it. The resulting WriteCloser must be closed after the contents of the file have been written.
// The to argument contains recipients that are explicitly mentioned in signatures and encrypted keys,
// whereas the toHidden argument contains recipients that will be hidden and not mentioned.
// Params contains all optional parameters.
func EncryptWithParams(ciphertext io.Writer, to, toHidden []*Entity, params *EncryptParams) (plaintext io.WriteCloser, err error) {
	if params == nil {
		params = &EncryptParams{}
	}
	if params.KeyWriter == nil {
		params.KeyWriter = ciphertext
	}
	return encrypt(to, toHidden, ciphertext, params)
}

// EncryptText encrypts a message to a number of recipients and, optionally,
// signs it. Optional information is contained in 'hints', also encrypted, that
// aids the recipients in processing the message. The resulting WriteCloser
// must be closed after the contents of the file have been written. If config
// The to argument contains recipients that are explicitly mentioned in signatures and encrypted keys,
// whereas the toHidden argument contains recipients that will be hidden and not mentioned.
// is nil, sensible defaults will be used. The signing is done in text mode.
func EncryptText(ciphertext io.Writer, to, toHidden []*Entity, signed *Entity, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncryptWithParams(ciphertext, to, toHidden, &EncryptParams{
		Signed:  signed,
		Hints:   hints,
		Config:  config,
		TextSig: true,
	})
}

// Encrypt encrypts a message to a number of recipients and, optionally, signs
// it. hints contains optional information, that is also encrypted, that aids
// the recipients in processing the message. The resulting WriteCloser must
// be closed after the contents of the file have been written.
// The to argument contains recipients that are explicetly mentioned in signatures and encrypted keys,
// whereas the toHidden argument contains recipents that will be hidden and not mentioned.
// If config is nil, sensible defaults will be used.
func Encrypt(ciphertext io.Writer, to, toHidden []*Entity, signed *Entity, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncryptWithParams(ciphertext, to, toHidden, &EncryptParams{
		Signed: signed,
		Hints:  hints,
		Config: config,
	})
}

// EncryptSplit encrypts a message to a number of recipients and, optionally, signs
// it. hints contains optional information, that is also encrypted, that aids
// the recipients in processing the message. The resulting WriteCloser must
// be closed after the contents of the file have been written.
// The to argument contains recipients that are explicetly mentioned in signatures and encrypted keys,
// whereas the toHidden argument contains recipents that will be hidden and not mentioned.
// If config is nil, sensible defaults will be used.
func EncryptSplit(keyWriter io.Writer, dataWriter io.Writer, to, toHidden []*Entity, signed *Entity, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncryptWithParams(dataWriter, to, toHidden, &EncryptParams{
		KeyWriter: keyWriter,
		Signed:    signed,
		Hints:     hints,
		Config:    config,
	})
}

// EncryptTextSplit encrypts a message to a number of recipients and, optionally, signs
// it. hints contains optional information, that is also encrypted, that aids
// the recipients in processing the message. The resulting WriteCloser must
// be closed after the contents of the file have been written.
// The to argument contains recipients that are explicetly mentioned in signatures and encrypted keys,
// whereas the toHidden argument contains recipents that will be hidden and not mentioned.
// If config is nil, sensible defaults will be used.
func EncryptTextSplit(keyWriter io.Writer, dataWriter io.Writer, to, toHidden []*Entity, signed *Entity, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	return EncryptWithParams(dataWriter, to, toHidden, &EncryptParams{
		KeyWriter: keyWriter,
		Signed:    signed,
		Hints:     hints,
		Config:    config,
		TextSig:   true,
	})
}

// writeAndSign writes the data as a payload package and, optionally, signs
// it. hints contains optional information, that is also encrypted,
// that aids the recipients in processing the message. The resulting
// WriteCloser must be closed after the contents of the file have been
// written. If config is nil, sensible defaults will be used.
func writeAndSign(payload io.WriteCloser, candidateHashes []uint8, signed *Entity, hints *FileHints, sigType packet.SignatureType, intendedRecipients []*packet.Recipient, config *packet.Config) (plaintext io.WriteCloser, err error) {
	var signer *packet.PrivateKey
	if signed != nil {
		signKey, ok := signed.SigningKeyById(config.Now(), config.SigningKey())
		if !ok {
			return nil, errors.InvalidArgumentError("no valid signing keys")
		}
		signer = signKey.PrivateKey
		if signer == nil {
			return nil, errors.InvalidArgumentError("no private key in signing key")
		}
		if signer.Encrypted {
			return nil, errors.InvalidArgumentError("signing key must be decrypted")
		}
	}

	var hash crypto.Hash
	for _, hashId := range candidateHashes {
		if h, ok := algorithm.HashIdToHash(hashId); ok && h.Available() {
			hash = h
			break
		}
	}

	// If the hash specified by config is a candidate, we'll use that.
	if configuredHash := config.Hash(); configuredHash.Available() {
		for _, hashId := range candidateHashes {
			if h, ok := algorithm.HashIdToHash(hashId); ok && h == configuredHash {
				hash = h
				break
			}
		}
	}

	if hash == 0 {
		hashId := candidateHashes[0]
		name, ok := algorithm.HashIdToString(hashId)
		if !ok {
			name = "#" + strconv.Itoa(int(hashId))
		}
		return nil, errors.InvalidArgumentError("cannot encrypt because no candidate hash functions are compiled in. (Wanted " + name + " in this case.)")
	}

	var salt []byte
	if signer != nil {
		var opsVersion = 3
		if signer.Version == 6 {
			opsVersion = signer.Version
		}
		ops := &packet.OnePassSignature{
			Version:    opsVersion,
			SigType:    sigType,
			Hash:       hash,
			PubKeyAlgo: signer.PubKeyAlgo,
			KeyId:      signer.KeyId,
			IsLast:     true,
		}
		if opsVersion == 6 {
			ops.KeyFingerprint = signer.Fingerprint
			salt, err = packet.SignatureSaltForHash(hash, config.Random())
			if err != nil {
				return nil, err
			}
			ops.Salt = salt
		}
		if err := ops.Serialize(payload); err != nil {
			return nil, err
		}
	}

	if hints == nil {
		hints = &FileHints{}
	}

	w := payload
	if signer != nil {
		// If we need to write a signature packet after the literal
		// data then we need to stop literalData from closing
		// encryptedData.
		w = noOpCloser{w}

	}
	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}
	literalData, err := packet.SerializeLiteral(w, hints.IsUTF8, hints.FileName, epochSeconds)
	if err != nil {
		return nil, err
	}

	if signer != nil {
		h, wrappedHash, err := hashForSignature(hash, sigType, salt)
		if err != nil {
			return nil, err
		}
		metadata := &packet.LiteralData{
			Format:   'b',
			FileName: hints.FileName,
			Time:     epochSeconds,
		}
		if hints.IsUTF8 {
			metadata.Format = 'u'
		}
		return signatureWriter{payload, literalData, hash, wrappedHash, h, salt, signer, sigType, config, metadata, intendedRecipients}, nil
	}
	return literalData, nil
}

// encrypt encrypts a message to a number of recipients and, optionally, signs
// it. The resulting WriteCloser must
// be closed after the contents of the file have been written.
func encrypt(
	to, toHidden []*Entity,
	dataWriter io.Writer,
	params *EncryptParams,
) (plaintext io.WriteCloser, err error) {
	if len(to)+len(toHidden) == 0 {
		return nil, errors.InvalidArgumentError("no encryption recipient provided")
	}

	// These are the possible ciphers that we'll use for the message.
	candidateCiphers := []uint8{
		uint8(packet.CipherAES256),
		uint8(packet.CipherAES128),
	}

	// These are the possible hash functions that we'll use for the signature.
	candidateHashes := []uint8{
		hashToHashId(crypto.SHA256),
		hashToHashId(crypto.SHA384),
		hashToHashId(crypto.SHA512),
		hashToHashId(crypto.SHA3_256),
		hashToHashId(crypto.SHA3_512),
	}

	// Prefer GCM if everyone supports it
	candidateCipherSuites := [][2]uint8{
		{uint8(packet.CipherAES256), uint8(packet.AEADModeGCM)},
		{uint8(packet.CipherAES256), uint8(packet.AEADModeEAX)},
		{uint8(packet.CipherAES256), uint8(packet.AEADModeOCB)},
		{uint8(packet.CipherAES128), uint8(packet.AEADModeGCM)},
		{uint8(packet.CipherAES128), uint8(packet.AEADModeEAX)},
		{uint8(packet.CipherAES128), uint8(packet.AEADModeOCB)},
	}

	candidateCompression := []uint8{
		uint8(packet.CompressionNone),
		uint8(packet.CompressionZIP),
		uint8(packet.CompressionZLIB),
	}

	encryptKeys := make([]Key, len(to)+len(toHidden))

	config := params.Config
	// AEAD is used only if config enables it and every key supports it
	aeadSupported := config.AEAD() != nil

	var intendedRecipients []*packet.Recipient
	// Intended Recipient Fingerprint subpacket SHOULD be used when creating a signed and encrypted message
	for _, publicRecipient := range to {
		intendedRecipients = append(intendedRecipients, &packet.Recipient{KeyVersion: publicRecipient.PrimaryKey.Version, Fingerprint: publicRecipient.PrimaryKey.Fingerprint})
	}

	for i, recipient := range append(to, toHidden...) {
		var ok bool
		encryptKeys[i], ok = recipient.EncryptionKey(config.Now())
		if !ok {
			return nil, errors.InvalidArgumentError("cannot encrypt a message to key id " + strconv.FormatUint(to[i].PrimaryKey.KeyId, 16) + " because it has no valid encryption keys")
		}

		primarySelfSignature, _ := recipient.PrimarySelfSignature()
		if primarySelfSignature == nil {
			return nil, errors.InvalidArgumentError("entity without a self-signature")
		}

		if primarySelfSignature.SEIPDv2 == false {
			aeadSupported = false
		}

		candidateCiphers = intersectPreferences(candidateCiphers, primarySelfSignature.PreferredSymmetric)
		candidateHashes = intersectPreferences(candidateHashes, primarySelfSignature.PreferredHash)
		candidateCipherSuites = intersectCipherSuites(candidateCipherSuites, primarySelfSignature.PreferredCipherSuites)
		candidateCompression = intersectPreferences(candidateCompression, primarySelfSignature.PreferredCompression)
	}

	// In the event that the intersection of supported algorithms is empty we use the ones
	// labelled as MUST that every implementation supports.
	if len(candidateCiphers) == 0 {
		// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#section-9.3
		candidateCiphers = []uint8{uint8(packet.CipherAES128)}
	}
	if len(candidateHashes) == 0 {
		// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#hash-algos
		candidateHashes = []uint8{hashToHashId(crypto.SHA256)}
	}
	if len(candidateCipherSuites) == 0 {
		// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#section-9.6
		candidateCipherSuites = [][2]uint8{{uint8(packet.CipherAES128), uint8(packet.AEADModeOCB)}}
	}

	cipher := packet.CipherFunction(candidateCiphers[0])
	aeadCipherSuite := packet.CipherSuite{
		Cipher: packet.CipherFunction(candidateCipherSuites[0][0]),
		Mode:   packet.AEADMode(candidateCipherSuites[0][1]),
	}

	// If the cipher specified by config is a candidate, we'll use that.
	configuredCipher := config.Cipher()
	for _, c := range candidateCiphers {
		cipherFunc := packet.CipherFunction(c)
		if cipherFunc == configuredCipher {
			cipher = cipherFunc
			break
		}
	}

	if params.SessionKey == nil {
		params.SessionKey = make([]byte, cipher.KeySize())
		if _, err := io.ReadFull(config.Random(), params.SessionKey); err != nil {
			return nil, err
		}
		defer func() {
			// zero the session key after we are done
			for i, _ := range params.SessionKey {
				params.SessionKey[i] = 0
			}
			params.SessionKey = nil
		}()
	}

	for idx, key := range encryptKeys {
		// hide the keys of the hidden recipients
		hidden := idx >= len(to)
		if err := packet.SerializeEncryptedKeyAEAD(params.KeyWriter, key.PublicKey, cipher, aeadSupported, params.SessionKey, hidden, config); err != nil {
			return nil, err
		}
	}

	return encryptDataAndSign(dataWriter, params, candidateHashes, candidateCompression, cipher, aeadSupported, aeadCipherSuite, intendedRecipients)
}

func encryptDataAndSign(
	dataWriter io.Writer,
	params *EncryptParams,
	candidateHashes, candidateCompression []uint8,
	cipher packet.CipherFunction,
	aeadSupported bool,
	aeadCipherSuite packet.CipherSuite,
	intendedRecipients []*packet.Recipient,
) (plaintext io.WriteCloser, err error) {
	sigType := packet.SigTypeBinary
	if params.TextSig {
		sigType = packet.SigTypeText
	}
	payload, err := packet.SerializeSymmetricallyEncrypted(dataWriter, cipher, aeadSupported, aeadCipherSuite, params.SessionKey, params.Config)
	if err != nil {
		return
	}
	payload, err = handleCompression(payload, candidateCompression, params.Config)
	if err != nil {
		return nil, err
	}
	return writeAndSign(payload, candidateHashes, params.Signed, params.Hints, sigType, intendedRecipients, params.Config)
}

// Sign signs a message. The resulting WriteCloser must be closed after the
// contents of the file have been written.  hints contains optional information
// that aids the recipients in processing the message.
// If config is nil, sensible defaults will be used.
func Sign(output io.Writer, signed *Entity, hints *FileHints, config *packet.Config) (input io.WriteCloser, err error) {
	if signed == nil {
		return nil, errors.InvalidArgumentError("no signer provided")
	}

	// These are the possible hash functions that we'll use for the signature.
	candidateHashes := []uint8{
		hashToHashId(crypto.SHA256),
		hashToHashId(crypto.SHA384),
		hashToHashId(crypto.SHA512),
		hashToHashId(crypto.SHA3_256),
		hashToHashId(crypto.SHA3_512),
	}
	defaultHashes := candidateHashes[0:1]
	primarySelfSignature, _ := signed.PrimarySelfSignature()
	if primarySelfSignature == nil {
		return nil, errors.InvalidArgumentError("signed entity has no self-signature")
	}
	preferredHashes := primarySelfSignature.PreferredHash
	if len(preferredHashes) == 0 {
		preferredHashes = defaultHashes
	}
	candidateHashes = intersectPreferences(candidateHashes, preferredHashes)
	if len(candidateHashes) == 0 {
		return nil, errors.InvalidArgumentError("cannot sign because signing key shares no common algorithms with candidate hashes")
	}

	return writeAndSign(noOpCloser{output}, candidateHashes, signed, hints, packet.SigTypeBinary, nil, config)
}

// signatureWriter hashes the contents of a message while passing it along to
// literalData. When closed, it closes literalData, writes a signature packet
// to encryptedData and then also closes encryptedData.
type signatureWriter struct {
	encryptedData      io.WriteCloser
	literalData        io.WriteCloser
	hashType           crypto.Hash
	wrappedHash        hash.Hash
	h                  hash.Hash
	salt               []byte // v6 only
	signer             *packet.PrivateKey
	sigType            packet.SignatureType
	config             *packet.Config
	metadata           *packet.LiteralData // V5 signatures protect document metadata
	intendedRecipients []*packet.Recipient
}

func (s signatureWriter) Write(data []byte) (int, error) {
	s.wrappedHash.Write(data)
	switch s.sigType {
	case packet.SigTypeBinary:
		return s.literalData.Write(data)
	case packet.SigTypeText:
		flag := 0
		return writeCanonical(s.literalData, data, &flag)
	}
	return 0, errors.UnsupportedError("unsupported signature type: " + strconv.Itoa(int(s.sigType)))
}

func (s signatureWriter) Close() error {
	sig := createSignaturePacket(&s.signer.PublicKey, s.sigType, s.config)
	sig.Hash = s.hashType
	sig.Metadata = s.metadata
	sig.IntendedRecipients = s.intendedRecipients

	if err := sig.SetSalt(s.salt); err != nil {
		return err
	}

	if err := sig.Sign(s.h, s.signer, s.config); err != nil {
		return err
	}
	if err := s.literalData.Close(); err != nil {
		return err
	}
	if err := sig.Serialize(s.encryptedData); err != nil {
		return err
	}
	return s.encryptedData.Close()
}

func createSignaturePacket(signer *packet.PublicKey, sigType packet.SignatureType, config *packet.Config) *packet.Signature {
	sigLifetimeSecs := config.SigLifetime()
	return &packet.Signature{
		Version:           signer.Version,
		SigType:           sigType,
		PubKeyAlgo:        signer.PubKeyAlgo,
		Hash:              config.Hash(),
		CreationTime:      config.Now(),
		IssuerKeyId:       &signer.KeyId,
		IssuerFingerprint: signer.Fingerprint,
		Notations:         config.Notations(),
		SigLifetimeSecs:   &sigLifetimeSecs,
	}
}

// noOpCloser is like an ioutil.NopCloser, but for an io.Writer.
// TODO: we have two of these in OpenPGP packages alone. This probably needs
// to be promoted somewhere more common.
type noOpCloser struct {
	w io.Writer
}

func (c noOpCloser) Write(data []byte) (n int, err error) {
	return c.w.Write(data)
}

func (c noOpCloser) Close() error {
	return nil
}

func handleCompression(compressed io.WriteCloser, candidateCompression []uint8, config *packet.Config) (data io.WriteCloser, err error) {
	data = compressed
	confAlgo := config.Compression()
	if confAlgo == packet.CompressionNone {
		return
	}

	// Set algorithm labelled as MUST as fallback
	// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#section-9.4
	finalAlgo := packet.CompressionNone
	// if compression specified by config available we will use it
	for _, c := range candidateCompression {
		if uint8(confAlgo) == c {
			finalAlgo = confAlgo
			break
		}
	}

	if finalAlgo != packet.CompressionNone {
		var compConfig *packet.CompressionConfig
		if config != nil {
			compConfig = config.CompressionConfig
		}
		data, err = packet.SerializeCompressed(compressed, finalAlgo, compConfig)
		if err != nil {
			return
		}
	}
	return data, nil
}
