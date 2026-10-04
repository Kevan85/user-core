#!/bin/sh
# Ajoute le DSN Sentry de la pré-production à service.env, de fichier à fichier, sans
# jamais l'afficher (C17 ; docs/ops/DEPLOIEMENT.md §7).
#
#   sh deploy/preprod/add-sentry-dsn.sh <fichier du DSN> /opt/user-core/preprod/secrets/service.env
#
# Le fichier du DSN vient du Bloc-notes : un BOM UTF-8 en tête et tout CR sont retirés,
# puis il doit porter EXACTEMENT UNE ligne non vide — un double collage est refusé. La
# FORME se contrôle par un compte, jamais la valeur : https://<clé de 32 caractères
# hexadécimaux>@<hôte>/<identifiant de projet>. Une forme ancienne (un secret dans le
# DSN) ou un hôte auto-hébergé sont refusés : c'est le bon sens de l'erreur.
#
# AUCUNE VALEUR N'EST AFFICHÉE, ni passée en argument d'une commande externe : elle ne
# circule que par des variables du shell, des tubes et printf, intégré au shell. Les
# messages ne disent que des formes et des comptes. Chaque contrôle échoue FERMÉ : un
# outil qui plante rend un compte vide, que le test refuse.
#
# L'écriture est ATOMIQUE : un temporaire du même répertoire reçoit la copie et l'ajout,
# se contrôle, puis remplace service.env. Un refus laisse service.env inchangé. Le script
# ne supprime PAS la source : la procédure le fait, une fois le boot de l'API prouvé
# (transport Sentry armé, G1).
set -eu
umask 077
export LC_ALL=C

usage='usage : add-sentry-dsn.sh <fichier du DSN> <service.env>'
source_dsn="${1:?$usage}"
cible="${2:?$usage}"
forme_dsn='^https://[0-9a-f]{32}@[A-Za-z0-9.-]+/[0-9]+$'
refus() {
  echo "REFUS : $1 — service.env inchangé" >&2
  exit 1
}

[ -f "$cible" ] || refus "service.env introuvable"
[ -f "$source_dsn" ] || refus "fichier du DSN introuvable"
deja=$(grep -c '^SENTRY_DSN=' "$cible" || true)
[ "$deja" -eq 0 ] || refus "service.env porte déjà ${deja:-?} ligne(s) SENTRY_DSN"

# Le BOM ne se retire qu'en TÊTE du fichier ; les CR, partout.
bom=$(printf '\357\273\277')
brut=$(tr -d '\r' < "$source_dsn")
propre=${brut#"$bom"}
lignes=$(printf '%s\n' "$propre" | grep -c . || true)
[ "$lignes" -eq 1 ] || refus "le fichier du DSN porte ${lignes:-?} ligne(s) non vide(s), une seule est attendue"
dsn=$(printf '%s\n' "$propre" | grep .)
forme=$(printf '%s\n' "$dsn" | grep -cE "$forme_dsn" || true)
[ "$forme" -eq 1 ] || refus "forme inattendue (attendue : https://<32 hexadécimaux>@<hôte>/<identifiant>)"

tmp="$(dirname "$cible")/.service.env.dsn.$$"
trap 'rm -f "$tmp"' EXIT
cp "$cible" "$tmp"
# Une dernière ligne sans fin de ligne collerait le DSN à la valeur qui la précède.
[ -z "$(tail -c 1 "$tmp")" ] || printf '\n' >> "$tmp"
printf 'SENTRY_DSN=%s\n' "$dsn" >> "$tmp"
total=$(grep -c '^SENTRY_DSN=' "$tmp" || true)
conformes=$(grep -cE "^SENTRY_DSN=${forme_dsn#^}" "$tmp" || true)
# Des ÉGALITÉS exigées, jamais des inégalités : un compte vide fait échouer le test, donc
# refuse — « -ne » le laisserait passer.
{ [ "$total" -eq 1 ] && [ "$conformes" -eq 1 ]; } \
  || refus "contrôle du temporaire : ${total:-?} ligne(s) SENTRY_DSN, ${conformes:-?} de forme conforme"
mv "$tmp" "$cible"
trap - EXIT
echo "SENTRY_DSN ajouté à $cible : 1 ligne de forme conforme — valeur non affichée"
