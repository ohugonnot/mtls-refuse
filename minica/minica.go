// Package minica est une mini autorité de certification en bibliothèque standard,
// faite pour les tests : elle émet des certificats feuilles aux défauts choisis
// (expiré, mauvais usage, numéro de série imposé) et des listes de révocation signées.
package minica

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// CA est une autorité racine. Elle ne sert que dans les tests : pas de persistance, pas de verrou.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
	next int64
}

// NewCA crée une racine dont le nom de sujet est commonName. Deux autorités créées
// avec le même nom ont le même sujet mais des clés différentes.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key, next: 100}, nil
}

// Pool renvoie un réservoir de confiance qui ne contient que cette autorité.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// LeafOptions décrit le certificat feuille voulu. Les champs à zéro prennent une valeur saine.
type LeafOptions struct {
	CommonName string
	NotBefore  time.Time
	NotAfter   time.Time
	// ExtKeyUsage vide = client seulement. Pour un certificat de serveur, passer ExtKeyUsageServerAuth.
	ExtKeyUsage []x509.ExtKeyUsage
	DNSNames    []string
	// Serial impose le numéro de série (utile pour fabriquer une collision entre deux autorités).
	Serial *big.Int
}

// Issue émet une feuille signée par l'autorité.
func (ca *CA) Issue(o LeafOptions) (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(time.Hour)
	}
	if len(o.ExtKeyUsage) == 0 {
		o.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	serial := o.Serial
	if serial == nil {
		ca.next++
		serial = big.NewInt(ca.next)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.CommonName},
		NotBefore:    o.NotBefore,
		NotAfter:     o.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.ExtKeyUsage,
		DNSNames:     o.DNSNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, nil
}

// CRL signe une liste de révocation numérotée qui contient les certificats donnés.
func (ca *CA) CRL(revoked []*x509.Certificate, number int64, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: thisUpdate})
	}
	tpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, tpl, ca.Cert, ca.key)
}
