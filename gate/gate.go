// Package gate construit la configuration TLS d'un serveur mTLS et la vérification de révocation
// qui va avec. Go vérifie la chaîne de confiance, la validité dans le temps et l'usage « client »,
// mais ne regarde jamais une liste de révocation : cette pièce-là est à écrire.
package gate

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// issuerID identifie une autorité par sa clé publique, pas par son nom : deux autorités peuvent
// porter le même nom de sujet, jamais la même clé.
type issuerID [32]byte

func idOf(ca *x509.Certificate) issuerID { return sha256.Sum256(ca.RawSubjectPublicKeyInfo) }

type list struct {
	number     *big.Int
	nextUpdate time.Time
	revoked    map[string]bool // numéro de série en décimal
}

// Revocation garde la dernière liste valide de chaque autorité de confiance.
type Revocation struct {
	mu    sync.RWMutex
	roots []*x509.Certificate
	lists map[issuerID]*list
	now   func() time.Time
}

// NewRevocation crée un registre pour les autorités données. Sans liste chargée, tout est refusé.
func NewRevocation(roots ...*x509.Certificate) *Revocation {
	return &Revocation{roots: roots, lists: map[issuerID]*list{}, now: time.Now}
}

// SetClock remplace l'horloge, pour les tests de péremption.
func (r *Revocation) SetClock(now func() time.Time) { r.now = now }

// Load vérifie puis installe une liste. Elle est refusée si aucune autorité de confiance ne l'a
// signée, si elle est déjà périmée, ou si son numéro n'est pas supérieur à celui de la liste en place.
func (r *Revocation) Load(der []byte) error {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("liste illisible : %w", err)
	}
	var signer *x509.Certificate
	for _, ca := range r.roots {
		if rl.CheckSignatureFrom(ca) == nil {
			signer = ca
			break
		}
	}
	if signer == nil {
		return errors.New("liste signée par aucune autorité de confiance")
	}
	if !rl.NextUpdate.After(r.now()) {
		return errors.New("liste déjà périmée")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := idOf(signer)
	if old := r.lists[id]; old != nil && rl.Number.Cmp(old.number) <= 0 {
		return fmt.Errorf("retour en arrière refusé : numéro %s, déjà en place %s", rl.Number, old.number)
	}
	l := &list{number: rl.Number, nextUpdate: rl.NextUpdate, revoked: map[string]bool{}}
	for _, e := range rl.RevokedCertificateEntries {
		l.revoked[e.SerialNumber.String()] = true
	}
	r.lists[id] = l
	return nil
}

// Check refuse une chaîne dont la feuille est révoquée par l'autorité qui l'a signée.
// Il refuse aussi quand l'autorité n'a aucune liste, ou une liste périmée : on ferme, on n'ouvre pas.
func (r *Revocation) Check(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return errors.New("chaîne sans autorité")
	}
	leaf, issuer := chain[0], chain[1]
	r.mu.RLock()
	defer r.mu.RUnlock()
	l := r.lists[idOf(issuer)]
	if l == nil {
		return errors.New("aucune liste de révocation pour cette autorité")
	}
	if !l.nextUpdate.After(r.now()) {
		return errors.New("liste de révocation périmée")
	}
	if l.revoked[leaf.SerialNumber.String()] {
		return fmt.Errorf("certificat %s révoqué", leaf.SerialNumber)
	}
	return nil
}

func (r *Revocation) checkState(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 {
		return errors.New("aucune chaîne vérifiée")
	}
	return r.Check(cs.VerifiedChains[0])
}

// ServerConfig renvoie la configuration d'un serveur qui exige un certificat client signé par clientCAs.
// La révocation se vérifie dans VerifyConnection, qui tourne aussi sur les connexions reprises.
func ServerConfig(server tls.Certificate, clientCAs *x509.CertPool, rev *Revocation) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{server},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		MinVersion:       tls.VersionTLS12,
		VerifyConnection: rev.checkState,
	}
}

// Middleware revérifie la révocation à chaque requête : une connexion longue (keep-alive, HTTP/2)
// ne refait pas de poignée de main, donc VerifyConnection ne la revoit plus.
func Middleware(rev *Revocation, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || rev.checkState(*req.TLS) != nil {
			http.Error(w, "certificat refusé", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, req)
	})
}
