#!/bin/sh
# Pose UNIQUE de la clé dédiée de User-Core sur le serveur partagé avec Scolaria. Le script
# se joue CÔTÉ SERVEUR, en une seule commande, par l'accès de Scolaria, une seule fois, sur
# l'autorisation de Kevin (docs/ops/DEPLOIEMENT.md §7.2) :
#
#   ssh -o BatchMode=yes scolaria-vps "$(git show <SHA>:deploy/preprod/add-authorized-key.sh)" \
#     < ~/.ssh/id_ed25519_user_core_preprod.pub
#
# Le script part de son BLOB (git show), jamais de la copie de travail : sous
# core.autocrlf=true, celle-ci peut être en CRLF, et un CR casserait chaque ligne côté
# serveur. La ligne publique arrive sur l'ENTRÉE STANDARD, jamais en argument.
#
# Le fichier visé porte l'accès administrateur de Scolaria : ce script ne fait qu'AJOUTER.
# Il refuse si sshd ne lit pas .ssh/authorized_keys, si l'entrée n'est pas une seule ligne
# « ssh-ed25519 … user-core-preprod », ou si la clé est déjà présente. Il mesure AVANT
# (lignes, octets, sha256, droits et propriétaire) et contrôle la FIN DE LIGNE finale : sans
# elle, la clé se COLLERAIT à la dernière clé existante et la casserait. Il mesure APRÈS, et
# chaque contrôle est une ÉGALITÉ exigée : le défaut est l'échec.
set -eu
f=/root/.ssh/authorized_keys
arret() { echo "ARRÊT : $1 — rien n'est écrit"; exit 1; }
echo "heure du serveur : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
akf=$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; print substr($0, 2) }')
case " $akf " in *" .ssh/authorized_keys "*) ;; *) arret "AuthorizedKeysFile effectif inattendu : « $akf »" ;; esac
[ -f "$f" ] || arret "$f absent"
n_avant=$(wc -l < "$f")
o_avant=$(wc -c < "$f")
sha_avant=$(sha256sum < "$f" | cut -c1-64)
droits_avant=$(stat -c '%a %U:%G' "$f")
rep_avant=$(stat -c '%a %U:%G' /root/.ssh)
umask 077
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
lignes=$(wc -l < "$tmp")
[ "$lignes" -eq 1 ] || arret "l'entrée standard porte $lignes ligne(s), une seule est attendue"
forme=$(grep -cE '^ssh-ed25519 [A-Za-z0-9+/]{68} user-core-preprod$' "$tmp" || true)
[ "$forme" -eq 1 ] || arret "ligne publique de forme inattendue"
deja=$(grep -cxF -f "$tmp" "$f" || true)
[ "$deja" -eq 0 ] || arret "cette clé est déjà présente"
# Sans fin de ligne finale, la clé se COLLERAIT à la dernière clé existante et la casserait.
if [ -z "$(tail -c 1 "$f")" ]; then fin=oui; else fin=NON; printf '\n' >> "$f"; fi
cat "$tmp" >> "$f"
n_apres=$(wc -l < "$f")
prefixe=$(head -c "$o_avant" "$f" | sha256sum | cut -c1-64)
premieres=$(head -n "$n_avant" "$f" | sha256sum | cut -c1-64)
if tail -n 1 "$f" | cmp -s - "$tmp"; then derniere=identique; else derniere=DIFFÉRENTE; fi
droits_apres=$(stat -c '%a %U:%G' "$f")
rep_apres=$(stat -c '%a %U:%G' /root/.ssh)
echo "AuthorizedKeysFile effectif : $akf"
echo "AVANT : $n_avant lignes, $o_avant octets, sha256=$sha_avant, droits du fichier=$droits_avant, du répertoire=$rep_avant, fin de ligne finale=$fin"
echo "APRÈS : $n_apres lignes ; sha256 des $o_avant premiers octets=$prefixe ; sha256 des $n_avant premières lignes=$premieres ; dernière ligne=$derniere ; droits du fichier=$droits_apres, du répertoire=$rep_apres"
ok=non
if [ "$prefixe" = "$sha_avant" ] && [ "$derniere" = identique ] && [ "$droits_apres" = "$droits_avant" ] && [ "$rep_apres" = "$rep_avant" ]; then
  if [ "$fin" = oui ]; then
    if [ "$n_apres" -eq $((n_avant + 1)) ] && [ "$premieres" = "$sha_avant" ]; then ok=oui; fi
  else
    if [ "$n_apres" -eq $((n_avant + 2)) ]; then ok=oui; fi
  fi
fi
echo "CONTRÔLES : $ok"
[ "$ok" = oui ]
