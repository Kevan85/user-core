#!/usr/bin/env bash
# NB : ce fichier vit dans tools/, HORS du périmètre des gardes (db/ src/
# scripts/) — il contient les motifs, il se ferait attraper lui-même.
# Les NEUF gardes contractuelles (CLAUDE.md §3.7, §3.8 + motifs H et I), jouées sur l'INDEX
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

run_guard "Motif H (un seul point d'assemblage des trousseaux)" -rnE \
  "USER_CORE_[A-Z_]+(_KEYS|_ACTIVE_KEY_ID)" \
  -- src/ scripts/ ':!src/crypto/keyring.ts'

# ---------------------------------------------------------------------------
# MOTIF I — TOUTE DOUBLURE ASSEMBLÉE PASSE PAR LE MUR (proposé le 21/08/2026 ;
# gravure au socle par l'Auditeur après merge).
#
# Les huit motifs ci-dessus exigent ZÉRO ligne. Celui-ci exige une PRÉSENCE :
# c'est le premier de cette forme, et c'est délibéré. Le trou qu'il ferme est
# celui de la leçon ① — le mur des doublures a été posé sur les deux points
# d'entrée d'aujourd'hui ; rien n'empêchait un TROISIÈME de naître sans lui,
# exactement comme la parade P4 est morte d'un second point de déchiffrement
# né trois lots plus tard, sans qu'aucun test ne rougisse.
#
# Périmètre src/ SEULEMENT : les tests utilisent les simulateurs, c'est leur
# métier — les soumettre au mur reviendrait à interdire de tester.
#
# FAIL-CLOSED SUR SON PROPRE OUTILLAGE (exigence de l'Auditeur) : le motif
# vérifie D'ABORD que la fonction de mur existe toujours, à son emplacement.
# Renommée, déplacée ou supprimée, le motif ROUGIT et force sa propre mise à
# jour — il ne passe jamais en silence en cherchant un nom qui n'existe plus.
GUARD_FN="declareSimulatedSeam"
GUARD_HOME="src/bootstrap/simulation.ts"
# Attrape './simulator/x', '../simulator/x', '../../dispatch/simulator/x',
# en import statique, dynamique ou require — apostrophes simples ET guillemets
# doubles : rien dans le dépôt n'impose un style de guillemet (ni .prettierrc ni
# règle quotes), donc un motif à apostrophe seule laisserait passer "./simulator/x".
SIMULATOR_IMPORT="(from|require\(|import\()[[:space:]]*['\"][^'\"]*simulator/"

if git grep --cached -qF "export function ${GUARD_FN}(" -- "$GUARD_HOME"; then
  importers=$(git grep --cached -lE "$SIMULATOR_IMPORT" -- src/ || true)
  missing=""
  for file in $importers; do
    if ! git grep --cached -q "$GUARD_FN" -- "$file"; then
      missing="$missing $file"
    fi
  done
  if [ -n "$missing" ]; then
    for file in $missing; do
      echo "  $file : assemble une doublure sans appeler $GUARD_FN"
    done
    echo "ÉCHEC — Motif I : une doublure est assemblée sans passer par le mur"
    status=1
  else
    echo "OK — Motif I (toute doublure assemblée passe par le mur)"
  fi
else
  echo "  $GUARD_HOME ne définit plus « export function $GUARD_FN »"
  echo "ÉCHEC — Motif I : le mur des doublures a été renommé, déplacé ou supprimé —"
  echo "        mets ce motif à jour AVANT de continuer (il refuse de chercher un nom mort)"
  status=1
fi

exit $status
