package openpgp

import (
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp/errors"
	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
)

// An Identity represents an identity claimed by an Entity and zero or more
// assertions by other entities about that claim.
type Identity struct {
	Primary             *Entity
	Name                string // by convention, has the form "Full Name (comment) <email@example.com>"
	UserId              *packet.UserId
	SelfCertifications  []*VerifiableSig
	OtherCertifications []*packet.Signature
	Revocations         []*VerifiableSig
}

func readUser(e *Entity, packets *packet.Reader, pkt *packet.UserId) error {
	identity := Identity{
		Primary: e,
		Name:    pkt.Id,
		UserId:  pkt,
	}

	for {
		p, err := packets.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		sig, ok := p.(*packet.Signature)
		if !ok {
			packets.Unread(p)
			break
		}

		if sig.SigType != packet.SigTypeGenericCert &&
			sig.SigType != packet.SigTypePersonaCert &&
			sig.SigType != packet.SigTypeCasualCert &&
			sig.SigType != packet.SigTypePositiveCert &&
			sig.SigType != packet.SigTypeCertificationRevocation {
			return errors.StructuralError("user ID signature with wrong type")
		}

		if sig.CheckKeyIdOrFingerprint(e.PrimaryKey) {
			if sig.SigType == packet.SigTypeCertificationRevocation {
				identity.Revocations = append(identity.Revocations, NewVerifiableSig(sig))
			} else {
				identity.SelfCertifications = append(identity.SelfCertifications, NewVerifiableSig(sig))
			}
			e.Identities[pkt.Id] = &identity
		} else {
			identity.OtherCertifications = append(identity.OtherCertifications, sig)
		}
	}
	return nil
}

func (i *Identity) Serialize(w io.Writer) error {
	if err := i.UserId.Serialize(w); err != nil {
		return err
	}
	for _, sig := range i.Revocations {
		if err := sig.Signature.Serialize(w); err != nil {
			return err
		}
	}
	for _, sig := range i.SelfCertifications {
		if err := sig.Signature.Serialize(w); err != nil {
			return err
		}
	}
	for _, sig := range i.OtherCertifications {
		if err := sig.Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

func (i *Identity) Verify(date time.Time) (selfSignature *packet.Signature, err error) {
	var zeroTime time.Time
	if selfSignature, err = i.getLatestValidSelfCertification(zeroTime); err != nil {
		return
	}
	if i.Revoked(date) {
		return nil, errors.StructuralError("user id is revoked")
	}
	return
}

// Revoked returns whether the identity has been revoked by a self-signature.
// Note that third-party revocation signatures are not supported.
func (i *Identity) Revoked(date time.Time) bool {
	// Verify revocations first
	for _, revocation := range i.Revocations {
		if !revocation.Verified {
			err := i.Primary.PrimaryKey.VerifyUserIdSignature(i.Name, i.Primary.PrimaryKey, revocation.Signature)
			revocation.Valid = err == nil
			revocation.Verified = true
		}
		if revocation.Signature.RevocationReason != nil && *revocation.Signature.RevocationReason == packet.KeyCompromised {
			// If the key is compromised, the key is considered revoked even before the revocation date.
			return true
		}
		if revocation.Valid && !revocation.Signature.SigExpired(date) {
			return true
		}
	}
	return false
}

func (i *Identity) ReSign(config *packet.Config) error {
	var timeZero time.Time
	selectedSig, err := i.getLatestValidSelfCertification(timeZero)
	if err != nil {
		return err
	}
	err = selectedSig.SignUserId(i.UserId.Id, i.Primary.PrimaryKey, i.Primary.PrivateKey, config)
	if err != nil {
		return err
	}
	return nil
}

func (i *Identity) getLatestValidSelfCertification(date time.Time) (selectedSig *packet.Signature, err error) {
	for sigIdx := len(i.SelfCertifications) - 1; sigIdx >= 0; sigIdx-- {
		sig := i.SelfCertifications[sigIdx]
		if (date.IsZero() || date.Unix() >= sig.Signature.CreationTime.Unix()) &&
			(selectedSig == nil || selectedSig.CreationTime.Unix() < sig.Signature.CreationTime.Unix()) {
			if !sig.Verified {
				err = i.Primary.PrimaryKey.VerifyUserIdSignature(i.Name, i.Primary.PrimaryKey, sig.Signature)
				sig.Valid = err == nil
				sig.Verified = true
			}
			if sig.Valid {
				selectedSig = sig.Signature
			}
		}
	}
	if selectedSig == nil {
		return nil, errors.StructuralError("no valid certification signature found for identity")
	}
	return
}
