// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	goerrors "errors"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp/armor"
	"github.com/ProtonMail/go-crypto/v2/openpgp/errors"
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
)

// PublicKeyType is the armor type for a PGP public key.
var PublicKeyType = "PGP PUBLIC KEY BLOCK"

// PrivateKeyType is the armor type for a PGP private key.
var PrivateKeyType = "PGP PRIVATE KEY BLOCK"

// An Entity represents the components of an OpenPGP key: a primary public key
// (which must be a signing key), one or more identities claimed by that key,
// and zero or more subkeys, which may be encryption keys.
type Entity struct {
	PrimaryKey       *packet.PublicKey
	PrivateKey       *packet.PrivateKey
	Identities       map[string]*Identity // indexed by Identity.Name
	Revocations      []*VerifiableSig
	DirectSignatures []*VerifiableSig // Direct-key self signature of the PrimaryKey (containts primary key properties in v6)}
	Subkeys          []Subkey
}

// A Key identifies a specific public key in an Entity. This is either the
// Entity's primary key or a subkey.
type Key struct {
	UsageTime     time.Time
	Entity        *Entity
	PublicKey     *packet.PublicKey
	PrivateKey    *packet.PrivateKey
	SelfSignature *packet.Signature
}

// A KeyRing provides access to public and private keys.
type KeyRing interface {
	// KeysById returns the set of keys that have the given key id.
	KeysById(id uint64) []Key
	// KeysByIdAndUsage returns the set of keys with the given id
	// that also meet the key usage given by requiredUsage.
	// The requiredUsage is expressed as the bitwise-OR of
	// packet.KeyFlag* values.
	KeysByIdUsage(id uint64, requiredUsage byte) []Key
	// DecryptionKeys returns all private keys that are valid for
	// decryption.
	DecryptionKeys() []Key
}

// PrimaryIdentity returns an Identity, preferring non-revoked identities,
// identities marked as primary, or the latest-created identity, in that order.
func (e *Entity) PrimaryIdentity(date time.Time) (*packet.Signature, *Identity, error) {
	var primaryIdentityCandidates []*Identity
	var primaryIdentityCandidatesSelfSigs []*packet.Signature
	for _, identity := range e.Identities {
		selfSig, err := identity.Verify(date)
		if err == nil { // verification is successful
			primaryIdentityCandidates = append(primaryIdentityCandidates, identity)
			primaryIdentityCandidatesSelfSigs = append(primaryIdentityCandidatesSelfSigs, selfSig)
		}
	}
	if len(primaryIdentityCandidates) == 0 {
		return nil, nil, errors.StructuralError("no primary identity found")
	}
	primaryIdentity := -1
	for idx := range primaryIdentityCandidates {
		if primaryIdentity == -1 ||
			shouldPreferIdentity(primaryIdentityCandidatesSelfSigs[idx],
				primaryIdentityCandidatesSelfSigs[idx]) {
			primaryIdentity = idx
		}
	}
	return primaryIdentityCandidatesSelfSigs[primaryIdentity], primaryIdentityCandidates[primaryIdentity], nil
}

func shouldPreferIdentity(existingId, potentialNewId *packet.Signature) bool {
	if existingId.IsPrimaryId != nil && *existingId.IsPrimaryId &&
		!(potentialNewId.IsPrimaryId != nil && *potentialNewId.IsPrimaryId) {
		return false
	}
	if !(existingId.IsPrimaryId != nil && *existingId.IsPrimaryId) &&
		potentialNewId.IsPrimaryId != nil && *potentialNewId.IsPrimaryId {
		return true
	}
	return potentialNewId.CreationTime.Unix() >= existingId.CreationTime.Unix()
}

// EncryptionKey returns the best candidate Key for encrypting a message to the
// given Entity.
func (e *Entity) EncryptionKey(now time.Time) (Key, bool) {
	// Fail to find any encryption key if the...
	primarySelfSignature, _, err := e.PrimarySelfSignature(now)
	if err != nil || // no self-signature found
		e.PrimaryKey.KeyExpired(primarySelfSignature, now) || // primary key has expired
		e.Revoked(now) || // primary key has been revoked
		primarySelfSignature.SigExpired(now) { // self-signature has expired
		return Key{}, false
	}

	// Iterate the keys to find the newest, unexpired one
	candidateSubkey := -1
	var candidateSubkeySelfSig *packet.Signature
	var maxTime time.Time
	for i, subkey := range e.Subkeys {
		subkeySelfSig, err := subkey.getLatestValidBindingSignature(now)
		if err != nil {
			return Key{}, false
		}
		if subkeySelfSig.FlagsValid &&
			subkeySelfSig.FlagEncryptCommunications &&
			subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
			subkey.Verify(now) == nil &&
			(maxTime.IsZero() || subkeySelfSig.CreationTime.Unix() >= maxTime.Unix()) {
			candidateSubkey = i
			candidateSubkeySelfSig = subkeySelfSig
			maxTime = subkeySelfSig.CreationTime
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return Key{now, e, subkey.PublicKey, subkey.PrivateKey, candidateSubkeySelfSig}, true
	}

	// If we don't have any subkeys for encryption and the primary key
	// is marked as OK to encrypt with, then we can use it.
	if primarySelfSignature.FlagsValid && primarySelfSignature.FlagEncryptCommunications &&
		e.PrimaryKey.PubKeyAlgo.CanEncrypt() {
		return Key{now, e, e.PrimaryKey, e.PrivateKey, primarySelfSignature}, true
	}

	return Key{}, false
}

// CertificationKey return the best candidate Key for certifying a key with this
// Entity.
func (e *Entity) CertificationKey(now time.Time) (Key, bool) {
	return e.CertificationKeyById(now, 0)
}

// CertificationKeyById return the Key for key certification with this
// Entity and keyID.
func (e *Entity) CertificationKeyById(now time.Time, id uint64) (Key, bool) {
	return e.signingKeyByIdUsage(now, id, packet.KeyFlagCertify)
}

// SigningKey return the best candidate Key for signing a message with this
// Entity.
func (e *Entity) SigningKey(now time.Time) (Key, bool) {
	return e.SigningKeyById(now, 0)
}

// SigningKeyById return the Key for signing a message with this
// Entity and keyID.
func (e *Entity) SigningKeyById(now time.Time, id uint64) (Key, bool) {
	return e.signingKeyByIdUsage(now, id, packet.KeyFlagSign)
}

func (e *Entity) signingKeyByIdUsage(now time.Time, id uint64, flags int) (Key, bool) {
	// Fail to find any signing key if the...
	primarySelfSignature, _, err := e.PrimarySelfSignature(now)
	if err != nil || // no self-signature found
		e.PrimaryKey.KeyExpired(primarySelfSignature, now) || // primary key has expired
		e.Revoked(now) || // primary key has been revoked
		primarySelfSignature.SigExpired(now) { // self-signature has expired
		return Key{}, false
	}

	// Iterate the keys to find the newest, unexpired one
	candidateSubkey := -1
	var candidateSubkeySelfSig *packet.Signature
	var maxTime time.Time
	for idx, subkey := range e.Subkeys {
		subkeySelfSig, err := subkey.getLatestValidBindingSignature(now)
		if err == nil &&
			subkeySelfSig.FlagsValid &&
			(flags&packet.KeyFlagCertify == 0 || subkeySelfSig.FlagCertify) &&
			(flags&packet.KeyFlagSign == 0 || subkeySelfSig.FlagSign) &&
			subkey.PublicKey.PubKeyAlgo.CanSign() &&
			subkey.Verify(now) == nil &&
			(maxTime.IsZero() || subkeySelfSig.CreationTime.Unix() >= maxTime.Unix()) &&
			(id == 0 || subkey.PublicKey.KeyId == id) {
			candidateSubkey = idx
			candidateSubkeySelfSig = subkeySelfSig
			maxTime = subkeySelfSig.CreationTime
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return Key{now, e, subkey.PublicKey, subkey.PrivateKey, candidateSubkeySelfSig}, true
	}

	// If we don't have any subkeys for signing and the primary key
	// is marked as OK to sign with, then we can use it.
	if primarySelfSignature.FlagsValid &&
		(flags&packet.KeyFlagCertify == 0 || primarySelfSignature.FlagCertify) &&
		(flags&packet.KeyFlagSign == 0 || primarySelfSignature.FlagSign) &&
		e.PrimaryKey.PubKeyAlgo.CanSign() &&
		(id == 0 || e.PrimaryKey.KeyId == id) {
		return Key{now, e, e.PrimaryKey, e.PrivateKey, primarySelfSignature}, true
	}

	// No keys with a valid Signing Flag or no keys matched the id passed in
	return Key{}, false
}

func revoked(revocations []*packet.Signature, now time.Time) bool {
	for _, revocation := range revocations {
		if revocation.RevocationReason != nil && *revocation.RevocationReason == packet.KeyCompromised {
			// If the key is compromised, the key is considered revoked even before the revocation date.
			return true
		}
		if !revocation.SigExpired(now) {
			return true
		}
	}
	return false
}

// Revoked returns whether the entity has any direct key revocation signatures.
// Note that third-party revocation signatures are not supported.
// Note also that Identity and Subkey revocation should be checked separately.
func (e *Entity) Revoked(now time.Time) bool {
	// Verify revocations first
	for _, revocation := range e.Revocations {
		if !revocation.Verified {
			err := e.PrimaryKey.VerifyRevocationSignature(revocation.Signature)
			revocation.Valid = err == nil
			revocation.Verified = true
		}
		if revocation.Signature.RevocationReason != nil && *revocation.Signature.RevocationReason == packet.KeyCompromised {
			// If the key is compromised, the key is considered revoked even before the revocation date.
			return true
		}
		if revocation.Valid && !revocation.Signature.SigExpired(now) {
			return true
		}
	}
	return false
}

// EncryptPrivateKeys encrypts all non-encrypted keys in the entity with the same key
// derived from the provided passphrase. Public keys and dummy keys are ignored,
// and don't cause an error to be returned.
func (e *Entity) EncryptPrivateKeys(passphrase []byte, config *packet.Config) error {
	var keysToEncrypt []*packet.PrivateKey
	// Add entity private key to encrypt.
	if e.PrivateKey != nil && !e.PrivateKey.Dummy() && !e.PrivateKey.Encrypted {
		keysToEncrypt = append(keysToEncrypt, e.PrivateKey)
	}

	// Add subkeys to encrypt.
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && !sub.PrivateKey.Encrypted {
			keysToEncrypt = append(keysToEncrypt, sub.PrivateKey)
		}
	}
	return packet.EncryptPrivateKeys(keysToEncrypt, passphrase, config)
}

// DecryptPrivateKeys decrypts all encrypted keys in the entitiy with the given passphrase.
// Avoids recomputation of similar s2k key derivations. Public keys and dummy keys are ignored,
// and don't cause an error to be returned.
func (e *Entity) DecryptPrivateKeys(passphrase []byte) error {
	var keysToDecrypt []*packet.PrivateKey
	// Add entity private key to decrypt.
	if e.PrivateKey != nil && !e.PrivateKey.Dummy() && e.PrivateKey.Encrypted {
		keysToDecrypt = append(keysToDecrypt, e.PrivateKey)
	}

	// Add subkeys to decrypt.
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && sub.PrivateKey.Encrypted {
			keysToDecrypt = append(keysToDecrypt, sub.PrivateKey)
		}
	}
	return packet.DecryptPrivateKeys(keysToDecrypt, passphrase)
}

// Revoked returns whether the key or subkey has been revoked by a self-signature.
// Note that third-party revocation signatures are not supported.
// Note also that Identity revocation should be checked separately.
// Normally, it's not necessary to call this function, except on keys returned by
// KeysById or KeysByIdUsage.
func (key *Key) Revoked(now time.Time) bool {
	return revoked(key.Revocations, now)
}

// An EntityList contains one or more Entities.
type EntityList []*Entity

// KeysById returns the set of keys that have the given key id.
func (el EntityList) KeysById(id uint64) (keys []Key) {
	for _, e := range el {
		if e.PrimaryKey.KeyId == id {
			selfSig, _ := e.PrimarySelfSignature()
			keys = append(keys, Key{e, e.PrimaryKey, e.PrivateKey, selfSig, e.Revocations})
		}

		for _, subKey := range e.Subkeys {
			if subKey.PublicKey.KeyId == id {
				keys = append(keys, Key{e, subKey.PublicKey, subKey.PrivateKey, subKey.Sig, subKey.Revocations})
			}
		}
	}
	return
}

// KeysByIdAndUsage returns the set of keys with the given id that also meet
// the key usage given by requiredUsage.  The requiredUsage is expressed as
// the bitwise-OR of packet.KeyFlag* values.
func (el EntityList) KeysByIdUsage(id uint64, requiredUsage byte) (keys []Key) {
	for _, key := range el.KeysById(id) {
		if requiredUsage != 0 {
			if key.SelfSignature == nil || !key.SelfSignature.FlagsValid {
				continue
			}

			var usage byte
			if key.SelfSignature.FlagCertify {
				usage |= packet.KeyFlagCertify
			}
			if key.SelfSignature.FlagSign {
				usage |= packet.KeyFlagSign
			}
			if key.SelfSignature.FlagEncryptCommunications {
				usage |= packet.KeyFlagEncryptCommunications
			}
			if key.SelfSignature.FlagEncryptStorage {
				usage |= packet.KeyFlagEncryptStorage
			}
			if usage&requiredUsage != requiredUsage {
				continue
			}
		}

		keys = append(keys, key)
	}
	return
}

// DecryptionKeys returns all private keys that are valid for decryption.
func (el EntityList) DecryptionKeys() (keys []Key) {
	for _, e := range el {
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil && subKey.Sig.FlagsValid && (subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications) {
				keys = append(keys, Key{e, subKey.PublicKey, subKey.PrivateKey, subKey.Sig, subKey.Revocations})
			}
		}
	}
	return
}

// ReadArmoredKeyRing reads one or more public/private keys from an armor keyring file.
func ReadArmoredKeyRing(r io.Reader) (EntityList, error) {
	block, err := armor.Decode(r)
	if err == io.EOF {
		return nil, errors.InvalidArgumentError("no armored data found")
	}
	if err != nil {
		return nil, err
	}
	if block.Type != PublicKeyType && block.Type != PrivateKeyType {
		return nil, errors.InvalidArgumentError("expected public or private key block, got: " + block.Type)
	}

	return ReadKeyRing(block.Body)
}

// ReadKeyRing reads one or more public/private keys. Unsupported keys are
// ignored as long as at least a single valid key is found.
func ReadKeyRing(r io.Reader) (el EntityList, err error) {
	packets := packet.NewReader(r)
	var lastUnsupportedError error

	for {
		var e *Entity
		e, err = ReadEntity(packets)
		if err != nil {
			// TODO: warn about skipped unsupported/unreadable keys
			if _, ok := err.(errors.UnsupportedError); ok {
				lastUnsupportedError = err
				err = readToNextPublicKey(packets)
			} else if _, ok := err.(errors.StructuralError); ok {
				// Skip unreadable, badly-formatted keys
				lastUnsupportedError = err
				err = readToNextPublicKey(packets)
			}
			if err == io.EOF {
				err = nil
				break
			}
			if err != nil {
				el = nil
				break
			}
		} else {
			el = append(el, e)
		}
	}

	if len(el) == 0 && err == nil {
		err = lastUnsupportedError
	}
	return
}

// readToNextPublicKey reads packets until the start of the entity and leaves
// the first packet of the new entity in the Reader.
func readToNextPublicKey(packets *packet.Reader) (err error) {
	var p packet.Packet
	for {
		p, err = packets.Next()
		if err == io.EOF {
			return
		} else if err != nil {
			if _, ok := err.(errors.UnsupportedError); ok {
				err = nil
				continue
			}
			return
		}

		if pk, ok := p.(*packet.PublicKey); ok && !pk.IsSubkey {
			packets.Unread(p)
			return
		}
	}
}

// ReadEntity reads an entity (public key, identities, subkeys etc) from the
// given Reader.
func ReadEntity(packets *packet.Reader) (*Entity, error) {
	e := new(Entity)
	e.Identities = make(map[string]*Identity)

	p, err := packets.Next()
	if err != nil {
		return nil, err
	}

	var ok bool
	if e.PrimaryKey, ok = p.(*packet.PublicKey); !ok {
		if e.PrivateKey, ok = p.(*packet.PrivateKey); !ok {
			packets.Unread(p)
			return nil, errors.StructuralError("first packet was not a public/private key")
		}
		e.PrimaryKey = &e.PrivateKey.PublicKey
	}

	if !e.PrimaryKey.PubKeyAlgo.CanSign() {
		return nil, errors.StructuralError("primary key cannot be used for signatures")
	}

	var revocations []*packet.Signature
	var directSignatures []*packet.Signature
EachPacket:
	for {
		p, err := packets.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		switch pkt := p.(type) {
		case *packet.UserId:
			err := readUser(e, packets, pkt)
			if err != nil {
				return nil, err
			}
		case *packet.Signature:
			if pkt.SigType == packet.SigTypeKeyRevocation {
				revocations = append(revocations, pkt)
			} else if pkt.SigType == packet.SigTypeDirectSignature {
				directSignatures = append(directSignatures, pkt)
			}
			// Else, ignoring the signature as it does not follow anything
			// we would know to attach it to.
		case *packet.PrivateKey:
			if !pkt.IsSubkey {
				packets.Unread(p)
				break EachPacket
			}
			err = readSubkey(e, packets, &pkt.PublicKey, pkt)
			if err != nil {
				return nil, err
			}
		case *packet.PublicKey:
			if !pkt.IsSubkey {
				packets.Unread(p)
				break EachPacket
			}
			err = readSubkey(e, packets, pkt, nil)
			if err != nil {
				return nil, err
			}
		default:
			// we ignore unknown packets
		}
	}

	if len(e.Identities) == 0 && e.PrimaryKey.Version < 6 {
		return nil, errors.StructuralError("v4 entity without any identities")
	}

	if e.PrimaryKey.Version == 6 && len(directSignatures) == 0 {
		return nil, errors.StructuralError("v6 entity without a  direct-key signature")
	}
	return e, nil
}

// SerializePrivate serializes an Entity, including private key material, but
// excluding signatures from other entities, to the given Writer.
// Identities and subkeys are re-signed in case they changed since NewEntry.
// If config is nil, sensible defaults will be used.
func (e *Entity) SerializePrivate(w io.Writer, config *packet.Config) (err error) {
	if e.PrivateKey.Dummy() {
		return errors.ErrDummyPrivateKey("dummy private key cannot re-sign identities")
	}
	return e.serializePrivate(w, config, true)
}

// SerializePrivateWithoutSigning serializes an Entity, including private key
// material, but excluding signatures from other entities, to the given Writer.
// Self-signatures of identities and subkeys are not re-signed. This is useful
// when serializing GNU dummy keys, among other things.
// If config is nil, sensible defaults will be used.
func (e *Entity) SerializePrivateWithoutSigning(w io.Writer, config *packet.Config) (err error) {
	return e.serializePrivate(w, config, false)
}

func (e *Entity) serializePrivate(w io.Writer, config *packet.Config, reSign bool) (err error) {
	if e.PrivateKey == nil {
		return goerrors.New("openpgp: private key is missing")
	}
	err = e.PrivateKey.Serialize(w)
	if err != nil {
		return
	}
	for _, revocation := range e.Revocations {
		if err = revocation.Signature.Serialize(w); err != nil {
			return err
		}
	}
	for _, directSignature := range e.DirectSignatures {
		if err = directSignature.Signature.Serialize(w); err != nil {
			return err
		}
	}
	for _, ident := range e.Identities {
		if reSign {
			if err = ident.ReSign(config); err != nil {
				return err
			}
		}
		if err = ident.Serialize(w); err != nil {
			return err
		}
	}
	for _, subkey := range e.Subkeys {
		if reSign {
			subkey.ReSign(config)
		}
		if err = subkey.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

// Serialize writes the public part of the given Entity to w, including
// signatures from other entities. No private key material will be output.
func (e *Entity) Serialize(w io.Writer) error {
	err := e.PrimaryKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, revocation := range e.Revocations {
		err := revocation.Serialize(w)
		if err != nil {
			return err
		}
	}
	for _, directSignature := range e.Signatures {
		err := directSignature.Serialize(w)
		if err != nil {
			return err
		}
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return err
		}
		for _, revocation := range subkey.Revocations {
			err := revocation.Serialize(w)
			if err != nil {
				return err
			}
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

// SignIdentity adds a signature to e, from signer, attesting that identity is
// associated with e. The provided identity must already be an element of
// e.Identities and the private key of signer must have been decrypted if
// necessary.
// If config is nil, sensible defaults will be used.
func (e *Entity) SignIdentity(identity string, signer *Entity, config *packet.Config) error {
	certificationKey, ok := signer.CertificationKey(config.Now())
	if !ok {
		return errors.InvalidArgumentError("no valid certification key found")
	}

	if certificationKey.PrivateKey.Encrypted {
		return errors.InvalidArgumentError("signing Entity's private key must be decrypted")
	}

	ident, ok := e.Identities[identity]
	if !ok {
		return errors.InvalidArgumentError("given identity string not found in Entity")
	}

	sig := createSignaturePacket(certificationKey.PublicKey, packet.SigTypeGenericCert, config)

	signingUserID := config.SigningUserId()
	if signingUserID != "" {
		if _, ok := signer.Identities[signingUserID]; !ok {
			return errors.InvalidArgumentError("signer identity string not found in signer Entity")
		}
		sig.SignerUserId = &signingUserID
	}

	if err := sig.SignUserId(identity, e.PrimaryKey, certificationKey.PrivateKey, config); err != nil {
		return err
	}
	ident.Signatures = append(ident.Signatures, sig)
	return nil
}

// RevokeKey generates a key revocation signature (packet.SigTypeKeyRevocation) with the
// specified reason code and text (RFC4880 section-5.2.3.23).
// If config is nil, sensible defaults will be used.
func (e *Entity) RevokeKey(reason packet.ReasonForRevocation, reasonText string, config *packet.Config) error {
	revSig := createSignaturePacket(e.PrimaryKey, packet.SigTypeKeyRevocation, config)
	revSig.RevocationReason = &reason
	revSig.RevocationReasonText = reasonText

	if err := revSig.RevokeKey(e.PrimaryKey, e.PrivateKey, config); err != nil {
		return err
	}
	e.Revocations = append(e.Revocations, revSig)
	return nil
}

// RevokeSubkey generates a subkey revocation signature (packet.SigTypeSubkeyRevocation) for
// a subkey with the specified reason code and text (RFC4880 section-5.2.3.23).
// If config is nil, sensible defaults will be used.
func (e *Entity) RevokeSubkey(sk *Subkey, reason packet.ReasonForRevocation, reasonText string, config *packet.Config) error {
	if err := e.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig); err != nil {
		return errors.InvalidArgumentError("given subkey is not associated with this key")
	}

	revSig := createSignaturePacket(e.PrimaryKey, packet.SigTypeSubkeyRevocation, config)
	revSig.RevocationReason = &reason
	revSig.RevocationReasonText = reasonText

	if err := revSig.RevokeSubkey(sk.PublicKey, e.PrivateKey, config); err != nil {
		return err
	}

	sk.Revocations = append(sk.Revocations, revSig)
	return nil
}

func (e *Entity) getLatestValidDirectSignature(date time.Time) (selectedSig *packet.Signature, err error) {
	for sigIdx := len(e.DirectSignatures) - 1; sigIdx >= 0; sigIdx-- {
		sig := e.DirectSignatures[sigIdx]
		if (date.IsZero() || date.Unix() >= sig.Signature.CreationTime.Unix()) &&
			(selectedSig == nil || selectedSig.CreationTime.Unix() < sig.Signature.CreationTime.Unix()) {
			if !sig.Verified {
				err := e.PrimaryKey.VerifyDirectKeySignature(sig.Signature)
				sig.Valid = err == nil
				sig.Verified = true
			}
			if sig.Valid {
				selectedSig = sig.Signature
			}
		}
	}
	if selectedSig == nil {
		return nil, errors.StructuralError("no valid direct key signature found")
	}
	return
}

// primarySelfSignature searches the entitity for the self-signature that stores key prefrences.
// For V4 keys, returns the self-signature of the primary indentity, and the identity.
// For V6 keys, returns the latest valid direct-key self-signature, and no identity (nil).
// This self-signature is to be used to check the key expiration,
// algorithm preferences, and so on.
func (e *Entity) PrimarySelfSignature(date time.Time) (primarySig *packet.Signature, primary *Identity, err error) {
	if e.PrimaryKey.Version == 6 {
		primarySig, err = e.getLatestValidDirectSignature(date)
		return
	}
	primarySig, primary, err = e.PrimaryIdentity(date)
	if err != nil {
		return
	}
	return
}
