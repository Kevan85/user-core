#!/usr/bin/env bash
# NB : ce fichier vit dans tools/, HORS du périmètre des gardes (db/ src/
# scripts/) — il contient les motifs, il se ferait attraper lui-même.
# Les SEPT gardes contractuelles (CLAUDE.md §3.7, §3.8), jouées sur l'INDEX
# git — exactement comme la CI les jouera sur le commit poussé. Les motifs
# sont recopiés VERBATIM de .github/workflows/ci.yml : si l'un des deux
# fichiers change, l'autre suit dans le même commit.
#
# Pourquoi ce script existe : les gardes ont attrapé deux fois du texte écrit
# dans un COMMENTAIRE (« la classe P0 » → motif B ; « la carte SIM » → motif A,
# car « carte » contient « cart »). Vérifier à la main, c'est oublier un jour ;
# et un `;` mal placé dans une chaîne de commandes laisse passer le commit.
# Ici, un seul point d'entrée : ça passe ou ça échoue.
#
# Usage : bash tools/check-guards.sh   (après git add, avant git commit)
set -u
status=0

run_guard() {
  local name="$1"; shift
  if git grep --cached "$@"; then
    echo "ÉCHEC — $name : motif détecté ci-dessus"
    status=1
  else
    echo "OK — $name"
  fi
}

run_guard "Motif A (termes de verticale)" -nE \
  "student|pupil|teacher|school|academic|patient|doctor|clinic|property|tenant|order|cart|enrollment|classroom|classId|class_id|\bfee\b|\bfees\b" \
  -- db/ src/ scripts/

run_guard "Motif B (class dans le schéma)" -nE \
  "(^|[^_])class" -- db/

run_guard "Garde anti-abonnement" -niE \
  "price|billing_cycle|next_renewal|subscription|invoice|\bamount\b|currency" \
  -- db/ src/ scripts/

run_guard "Motif D (PII + canal de preuve, sensible à la casse)" -nE \
  "phone_plain|phoneNumber|msisdn|WHATSAPP|whatsapp|whats_app" \
  -- db/ src/

run_guard "Motif E (zéro cycle — le dispatcher ne connaît aucune identité)" -nE \
  "account|phone|claim|session|from '\.\./(auth|phone|catalog|outbox|accounts)" \
  -- src/dispatch/

run_guard "Motif F (un seul point de déchiffrement)" -n \
  "decrypt(" \
  -- src/ ':!src/crypto/' ':!src/phone/verified-address.ts'

run_guard "Motif G (le cœur est agnostique du pays, sensible à la casse)" -nE \
  "post_nom|postNom|postnom|POST_NOM|\+243" \
  -- db/ src/

exit $status
