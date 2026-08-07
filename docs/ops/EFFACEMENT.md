# Effacement — ce que « effacé » veut dire, ce qui reste, et les gestes d'exploitation

> Runbook du LOT effacement (migrations `026→029`). Le **régime** (qui déclenche, le choix
> du délai, le préavis, le refus du dernier responsable) est verrouillé au CDC §10 n°14 —
> rien d'ici ne le remplace. Ici : ce qu'un opérateur doit savoir et faire.

## 1. Le circuit, en une page

- **Self (adulte/émancipé)** : `POST /account/erasure` — `DELAYED` (fenêtre de réflexion,
  paramètre `erasure_policy`, 7 jours) ou `IMMEDIATE` (exécuté dans l'appel).
  Rétractation : `DELETE /account/erasure`, jusqu'à l'échéance, en base (P0102 au-delà).
- **Staff (mineur / personne sans compte actif)** : `POST /staff/erasures`, par identifiant
  public. **IMMEDIATE est le seul mode de ce chemin** (G1) : un délai qui ne peut être ni
  annoncé ni rétracté n'est pas une fenêtre de réflexion.
- **Le worker** balaie `person_erasures` : préavis (`PERSON_ERASURE_IMMINENT`, déposé
  **dans le compte** — aucun canal externe : un SMS sur une ligne recyclée parlerait à un
  inconnu) à J-48 h, exécution à l'échéance par `erase_person()`.
- **L'exécution** : liens de responsabilité clos (`end_reason = 'ERASED'`) → revendications
  révoquées (`revoke_reason = 'ERASED'`) **puis** neutralisées → sel remplacé + blob à
  `NULL` → profil (`display_name`, `locale`) à `NULL` → **compte désactivé** (les sessions
  tombent par cascade) → registre marqué `COMPLETED`. L'ordre est **muré**, pas promis :
  `COMPLETED` refuse toute revendication vivante (026).

## 2. Les deux compteurs du worker — et ce qu'un humain en fait

- **`bloqués (mur)`** : P0114 — la personne est (re)devenue **dernier responsable** d'un
  ayant droit. État métier attendu ; la demande reste `REQUESTED`. **Le geste : un acte
  staff** — désigner un remplaçant (`end_responsibility` avec remplacement atomique), puis
  l'exécution passe au tick suivant. Ce compteur peut se répéter : c'est normal.
- **`en PANNE`** : tout le reste (connexion, interblocage, bug). **JAMAIS normal, toujours
  à investiguer** — ne pas le classer avec les bloqués : c'est précisément pour ça que les
  deux compteurs existent (G2).

## 3. « Effacé » veut dire « effacé à J+R » — et R est le MAXIMUM de toutes les couches

La crypto-destruction (sel remplacé, blob détruit) n'est **effective** qu'à l'expiration
de la rétention de **toutes** les copies : cf. [SAUVEGARDES.md §2/§3bis](SAUVEGARDES.md).
**Statut au 30/07/2026 : `R` est NON RÉPONDABLE — Kevin change d'hébergeur** (CDC §9 n°5).
Conséquences tenues par le code, à ne pas défaire :

- **aucune date d'effacement effectif n'est promise à une famille** (l'API n'expose que la
  fin de fenêtre de rétractation) ;
- la bascule d'hébergeur a **deux couches propres** à inventorier : la **copie de
  migration** (le dump transporté, celui qu'on garde « le temps de vérifier ») et les
  **snapshots de l'ancien hébergeur**, qui survivent régulièrement à la résiliation. La
  **destruction prouvée des données chez l'ancien** est une **ligne de contrôle de la
  bascule**, pas une intention ;
- le jour où `R` effectif est connu : la phrase communiquée à Kevin porte **le maximum de
  toutes les couches**, jamais le paramètre d'un script.

## 4. Les résidus ASSUMÉS — ce que l'effacement ne détruit PAS

À dire tel quel (le test de présence est **BORNÉ, pas FERMÉ**) :

| Résidu | Où | Pourquoi assumé |
|---|---|---|
| `birth_year` (année seule) | `persons` | Résidu déclaré dès 014 (finalité : borne d'âge) — ± 1 an |
| `public_identifier` | `persons`, `accounts` | Opaque CSPRNG, ne révèle rien seul |
| `secret_hash` (argon2id) | `account_secrets` | Non réversible ; le compte est désactivé |
| **`phone_hmac` dans TROIS registres append-only** | `possession_proof_refusals` (007), `program_invitations` (012), `program_invitation_refusals` (012) | Percer un `forbid_update` de registre coûterait plus qu'il ne rend (028, F1). **Quiconque détient un dump + le trousseau HMAC peut encore tester la présence d'un numéro via ces lignes-là** |
| `provider_ref` | `possession_proofs`, `proof_dispatches` | Référence chez le **fournisseur SMS** : sa rétention est une couche **externe**, hors de notre script |
| Le plafond par ligne se **détache** | `possession_proofs` via l'empreinte neutralisée | C7 : les preuves passées d'une ligne effacée ne comptent plus dans le plafond. Conséquence bornée (il faut s'effacer — irréversible — pour l'obtenir), et plutôt souhaitable : le nouveau porteur de la SIM n'hérite pas de l'historique d'un autre |
| L'**historique** des droits survit | `program_grants` | ⚠️ Depuis `033` les droits `ACTIFS` sont **coupés** (`revoke_reason = 'ERASED'`) — la dette E-1 est soldée. Mais les lignes **restent** : « ce programme a eu un droit sur cette personne, du tel au tel » demeure lisible. Registre append-only, `REVOKED` figé (P0103) — et les motifs d'époque (`SELF`, `PROGRAM`) ne sont **pas** réécrits : ils disaient vrai et continuent de le dire |
| Un programme voit `REVOKED`, **sans le motif** | façade `/v1/grants/status` | La façade n'expose que `status`, `grantedAt`, `revokedAt`. **L'ambiguïté repose sur DEUX valeurs atteignables — `SELF` et `ERASED`** : le jour où l'une cesse de l'être, `REVOKED` devient un **oracle d'effacement**. Un test tient cette condition en vie (`tests/persons/erasure-grant-wall.spec.ts`) |
| Les liens où l'effacé est **AYANT DROIT** | `person_responsibilities` | ⚠️ **Asymétrie mesurée, à ne pas confondre avec un oubli** : `erase_person` ne ferme que les liens où la personne est **RESPONSABLE** (`responsible_person_id`, geste 1). Ceux où elle est **ayant droit** restent `ACTIVE` — le devenir des liens de responsabilité **n'a pas été tranché**, et une décision ne s'étend jamais au-delà de ce qu'elle tranche |
| Le graphe familial survit | `person_responsibilities` | Des UUID sans PII — mais « qui était responsable de qui » reste lisible, avec `end_reason = 'ERASED'` sur les liens clos par l'effacement |
| Les **invitations de programme en cours** ne sont pas annulées | `program_invitations` | Mesuré : `erase_person` **n'écrit pas** dans cette table. Une invitation `PENDING` adressée à l'empreinte de la ligne reste ouverte jusqu'à son expiration — et cette empreinte est déjà nommée plus haut comme résidu de registre |

## 5. La garantie qui ne vit PAS en base (H1)

**L'énoncé d'irréversibilité du mode `IMMEDIATE` est porté par l'INTERFACE, pas par la
base** — la base ne peut pas vérifier qu'un humain a lu une phrase, et un paramètre
`p_acknowledged` ne prouverait rien (023). Tout **nouvel appelant** de
`request_erasure_self(…, 'IMMEDIATE')` — outil d'admin, script, v2 — reprend cette charge
à son compte. C'est la seule exception de ce lot à « l'invariant vit en base », et elle
est nommée partout où elle se joue (026, contrôleur, ici).

## 6. Restauration : une sauvegarde RÉ-INTRODUIT des effacés

Cf. [INCIDENT.md §4](INCIDENT.md) — la procédure et sa vérité inconfortable vivent là-bas.

## 7. Dette NOMMÉE, pas traitée

**E-1 — ce qu'un programme apprend quand une personne connue est effacée.**
**TRANCHÉE le 04/08/2026 : COUPER.** Livrée en deux étapes — `032` (le mur : un effacé ne
reçoit plus de droit) puis `033` (la coupure : les droits `ACTIFS` tombent en `ERASED`).

⚠️ **Mais la dette n'est soldée qu'à MOITIÉ, et il faut le dire tel quel.**

**Volet ÉTAT : FERMÉ** (`033`). Le droit d'une personne effacée n'est plus `ACTIVE`.

**Volet NOTIFICATION : ouvert, et ce n'est PAS un oubli.** Aucun fait sortant n'est émis —
mesuré : ni les portes de révocation, ni aucun des quatre triggers de `program_grants`
n'écrit dans `outbox` ou `account_notifications`, et c'est voulu (une ligne d'outbox
porterait le `person_id` d'un effacé). **Le seul mécanisme candidat est la surface d'accès
du contrat de comptes d'Organization-Core, dont notre avis du 03/08/2026 a montré qu'un
fait de changement y TRAHIRAIT l'effacement** au lieu de le taire : un tel fait n'aurait
aujourd'hui **qu'une seule cause possible**. C'est vérifiable ici, et c'est mesuré —
`UPDATE accounts` ne se trouve qu'à **un** endroit du dépôt (`028_erase_person.sql`), la
fermeture de compte étant suspendue (CDC §10 n°16) : rien d'autre que l'effacement ne rend
un compte indisponible.

→ **Ce volet ne se referme donc pas chez nous seuls : il vit dans le contrat.** En
attendant, **un programme qui veut savoir interroge** — et il lira `REVOKED` sans motif
(§4). Le point de greffe technique reste écrit dans l'en-tête d'`erase_person()` (`028`) :
la désactivation du compte, même transaction, là et nulle part ailleurs.
