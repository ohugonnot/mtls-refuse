#!/usr/bin/env bash
# Casse le code de dix façons, une à la fois, et vérifie que les tests rougissent.
# Usage (Go requis) : ./mutations.sh        Code retour 0 si toutes les mutations sont attrapées.
set -u
cd "$(dirname "$0")" || exit 2
G=gate/gate.go
cp "$G" "$G.orig"
trap 'mv "$G.orig" "$G"' EXIT
status=0
mutate() { # description, motif sed (appliqué à gate.go)
  cp "$G.orig" "$G"
  sed -i "$2" "$G"
  if cmp -s "$G" "$G.orig"; then echo "ERREUR : la mutation « $1 » n'a rien changé"; status=1; return; fi
  out=$(go test -count=1 ./e2e 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "NON ATTRAPEE : $1"; status=1
  elif echo "$out" | grep -q "build failed\|\[setup failed\]"; then
    echo "ERREUR : la mutation « $1 » ne compile pas, ce n'est pas un test qui rougit"; status=1
  else
    echo "attrapée     : $1"
  fi
}
mutate "le certificat client devient facultatif (VerifyClientCertIfGiven)" 's/tls.RequireAndVerifyClientCert/tls.VerifyClientCertIfGiven/'
mutate "la chaîne n'est plus vérifiée (RequireAnyClientCert)" 's/tls.RequireAndVerifyClientCert/tls.RequireAnyClientCert/'
mutate "la révocation passe de VerifyConnection à VerifyPeerCertificate" 's/VerifyConnection: rev.checkState,/VerifyPeerCertificate: func(_ [][]byte, c [][]*x509.Certificate) error { if len(c) == 0 { return nil }; return rev.Check(c[0]) },/'
mutate "la signature de la liste n'est plus vérifiée" 's/if rl.CheckSignatureFrom(ca) == nil {/if true {/'
mutate "le retour en arrière de la liste est accepté" 's/old != nil \&\& rl.Number.Cmp(old.number) <= 0/false/'
mutate "une liste périmée est crue (au contrôle)" 's/if !l.nextUpdate.After(r.now()) {/if false {/'
mutate "une autorité sans liste est acceptée (on ouvre au lieu de fermer)" 's/if l == nil {/if l == nil { return nil/'
mutate "les autorités sont identifiées par leur nom au lieu de leur clé" 's/return sha256.Sum256(ca.RawSubjectPublicKeyInfo)/return sha256.Sum256(ca.RawSubject)/'
mutate "le middleware ne vérifie plus rien" 's/rev.checkState(\*req.TLS) != nil/false/'
mutate "le numéro de série seul identifie un certificat (l'autorité est ignorée)" 's/return sha256.Sum256(ca.RawSubjectPublicKeyInfo)/return issuerID{sha256.Sum256(nil)[0]}/'
exit $status
