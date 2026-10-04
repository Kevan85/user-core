#!/bin/sh
# Fait naître les secrets de la pré-production SUR la machine qui s'en sert
# (CLAUDE.md §5 : aucun secret de production sur un poste de développement ;
# SECRETS.md §2 : chaque environnement génère SES valeurs, aucune ne circule).
#
#   sh deploy/preprod/generate-secrets.sh /opt/user-core/preprod/secrets
#
# AUCUNE VALEUR N'EST AFFICHÉE, ni passée en argument d'une commande — elle finirait
# dans un historique ou dans la liste des processus. Les valeurs vivent dans des
# variables du shell ; printf, intégré au shell, les écrit dans deux fichiers 600.
#
# Le DSN Sentry n'est PAS tiré ici : il vient de la console Sentry et s'ajoute à
# service.env de fichier à fichier, par deploy/preprod/add-sentry-dsn.sh.
#
# REFUS si l'un des deux fichiers existe : re-tirer les secrets d'une base déjà
# initialisée la rendrait inaccessible (mot de passe du propriétaire) et ses données
# chiffrées illisibles (trousseaux). Une rotation suit ROTATION.md, jamais ce script.
set -eu
umask 077

dir="${1:?usage : generate-secrets.sh <répertoire des secrets>}"
if [ -e "$dir/admin.env" ] || [ -e "$dir/service.env" ]; then
  echo "REFUS : $dir porte déjà admin.env ou service.env — rien n'est écrit" >&2
  exit 1
fi
mkdir -p "$dir"
chmod 700 "$dir"

cle_32() { openssl rand -base64 32; }
mot_de_passe() { openssl rand -hex 32; }
# Ed25519, PKCS8 DER, en base64 sur une ligne : la forme qu'attend AUTH_SIGNING_KEYS.
cle_signature() { openssl genpkey -algorithm ed25519 -outform DER | base64 -w0; }

# Tout est tiré AVANT d'écrire : une affectation qui échoue arrête le script (set -e),
# là où une substitution passée en argument de printf échouerait en silence.
proprietaire=$(mot_de_passe)
applicatif=$(mot_de_passe)
chiffrement=$(cle_32)
empreinte=$(cle_32)
codes=$(cle_32)
references=$(cle_32)
signature=$(cle_signature)

# Un contrôle de FORME, jamais de valeur : un outil qui rendrait vide ou tronqué
# n'écrit rien.
forme() {
  if [ "${#2}" -ne "$3" ]; then
    echo "REFUS : $1 n'a pas la forme attendue — rien n'est écrit" >&2
    exit 1
  fi
}
forme "mot de passe du propriétaire" "$proprietaire" 64
forme "mot de passe du rôle bridé" "$applicatif" 64
forme "clé de chiffrement" "$chiffrement" 44
forme "clé d'empreinte" "$empreinte" 44
forme "clé des codes de possession" "$codes" 44
forme "clé des références" "$references" 44
forme "clé de signature" "$signature" 64

tmp_admin="$dir/.admin.env.$$"
tmp_service="$dir/.service.env.$$"
trap 'rm -f "$tmp_admin" "$tmp_service"' EXIT
{
  printf 'POSTGRES_USER=user_core\n'
  printf 'POSTGRES_DB=user_core\n'
  printf 'POSTGRES_PASSWORD=%s\n' "$proprietaire"
  printf 'DATABASE_ADMIN_URL=postgres://user_core:%s@postgres:5432/user_core\n' "$proprietaire"
  printf 'USER_CORE_APP_PASSWORD=%s\n' "$applicatif"
} > "$tmp_admin"
{
  printf 'DATABASE_URL=postgres://user_core_app:%s@postgres:5432/user_core\n' "$applicatif"
  printf 'USER_CORE_ENC_KEYS={"E1":"%s"}\n' "$chiffrement"
  printf 'USER_CORE_ENC_ACTIVE_KEY_ID=E1\n'
  # H1 : l'identifiant gravé par 006 — assertFingerprintKeyAligned refuse tout autre.
  printf 'USER_CORE_HMAC_KEYS={"H1":"%s"}\n' "$empreinte"
  printf 'USER_CORE_HMAC_ACTIVE_KEY_ID=H1\n'
  printf 'USER_CORE_PROOF_CODE_KEYS={"C1":"%s"}\n' "$codes"
  printf 'USER_CORE_PROOF_CODE_ACTIVE_KEY_ID=C1\n'
  printf 'USER_CORE_REF_HMAC_KEYS={"R1":"%s"}\n' "$references"
  printf 'USER_CORE_REF_HMAC_ACTIVE_KEY_ID=R1\n'
  printf 'AUTH_SIGNING_KEYS={"S1":"%s"}\n' "$signature"
  printf 'AUTH_ACTIVE_KEY_ID=S1\n'
} > "$tmp_service"
mv "$tmp_admin" "$dir/admin.env"
mv "$tmp_service" "$dir/service.env"
trap - EXIT
echo "écrits : $dir/admin.env et $dir/service.env (600) — aucune valeur affichée ; le DSN reste à ajouter (add-sentry-dsn.sh)"
