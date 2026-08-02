# Incidents — les quatre cas nommés, et l'ordre des gestes

> Runbook d'exploitation (LOT prod, étape 7). Propriété : Exécuteur, sous `docs/ops/`.
> Règle transverse : chaque incident se TRACE (append-only — ce dépôt ne supprime rien),
> et chaque clôture répond à la question de la leçon ① : *« qu'est-ce qui empêchera ce
> trou de renaître ailleurs ? »* — la bonne réponse est une garde mécanique, jamais
> « on y pensera ».

## 1. Fuite de PII — le cas le plus grave : une donnée est partie chez un TIERS

Une fuite ne se rattrape pas ; l'ordre des gestes vise à borner, prouver, puis décider.

1. **COUPER le canal, d'abord.** Sentry : révoquer le DSN dans la console fournisseur
   (l'envoi meurt côté tiers, même si un service tourne encore). Dispatcher/worker :
   arrêter le worker (l'outbox retient — `PENDING` s'accumule sans perte, c'est son rôle).
   Logs : suspendre l'expédition externe s'il y en a une.
2. **QUALIFIER, en écrivant.** Quoi exactement (numéro, nom, date, jeton ?), par quel
   canal, depuis quand, combien de personnes — en comptant depuis les registres, jamais
   en supposant. La qualification se consigne horodatée : elle est la matière de la
   décision et du post-mortem.
3. **NE PAS purger côté tiers sans trace** : demander la suppression (Sentry sait purger
   des événements), mais consigner AVANT ce qui y était — la preuve d'abord.
4. **KEVIN décide de la suite externe** (information des personnes concernées,
   partenaires) : le régime volontaire strict (§3.14) vaut engagement même sans cadre
   légal RDC — on se comporte comme si l'obligation de notification existait. On lui
   apporte la qualification chiffrée, jamais « on pense que ».
5. **FERMER mécaniquement.** La faille rejoint une garde : un motif CI, un test-espion,
   un mur de boot. Une fuite passée par un chemin que l'espion ne couvrait pas =
   l'espion s'élargit dans le même correctif.

## 2. Compromission de clé — par trousseau, avec le J+R des dumps

Réflexe commun : rotation immédiate ([ROTATION.md](ROTATION.md)) + trace + qualification
de la fenêtre d'exposition. **Et toujours** : un dump antérieur porte ce que la clé
protégeait — **une clé compromise reste dangereuse J+R durant**
([SAUVEGARDES.md §3/§3bis](SAUVEGARDES.md)) ; l'audit des accès au dépôt de sauvegardes
fait partie de l'incident.

| Clé compromise | Gravité | Gestes spécifiques |
|---|---|---|
| **Chiffrement** (`ENC`) | 🔴 la PII au repos est lisible pour qui a AUSSI les données | Rotation ordinaire (les écritures neuves partent saines). Les valeurs déjà chiffrées restent lisibles par l'attaquant s'il obtient base ou dump → audit d'accès base + dumps ; re-chiffrement de masse = lot dédié, décision avec l'Auditeur. |
| **Empreinte téléphone** (`HMAC`) | 🔴 dump + cette clé = tous les numéros par force brute (espace énumérable) | Rotation EXCEPTIONNELLE, service arrêté (ROTATION.md §5, mur 025). Auditer les accès aux dumps ; la clé reste dangereuse J+R durant. |
| **Codes de possession** | 🟠 forger un code = voler une preuve de ligne EN COURS | Rotation simple (TTL 300 s). Vérifier les preuves passées ACTIVE dans la fenêtre d'exposition (registre `possession_proofs`, append-only). |
| **Références d'idempotence** | 🟠 fabriquer des re-clics « déjà vus » ou sonder l'idempotence | Rotation (l'idempotence traverse, 024). Aucune PII sous cette clé. |
| **Signature des jetons** (`AUTH_SIGNING_KEYS`) | 🔴 forger un jeton = être n'importe qui pendant ≤ 900 s | Rotation du kid + RETRAIT IMMÉDIAT de l'ancien (pas de recouvrement pour une clé compromise : les jetons legacy meurent, les clients se ré-authentifient). « Couper toutes les sessions » si le doute porte sur des sessions émises. |
| **Clé privée d'un programme** | 🟠 se faire passer pour CE programme | C'est SA clé (jamais détenue ici) : révoquer sa ligne (`program-client-admin.ts`), il ré-enregistre. Voir cas 3 si l'abus a eu lieu. |
| **Mots de passe Postgres** | 🔴 lecture directe de la base (PII chiffrée, empreintes en clair) | `ALTER ROLE … PASSWORD` immédiat + redéploiement + audit `pg_stat_activity`/logs d'accès. Le rôle bridé borne l'écriture, pas la lecture des empreintes → traiter comme le cas HMAC si l'accès est avéré. |

## 3. Révocation d'un programme (compromis ou en rupture de contrat)

1. **Révoquer son identité cliente** (`scripts/program-client-admin.ts`, append-only) :
   plus aucun jeton `/v1/token` — effet immédiat, les autres programmes sont intacts.
2. Les jetons déjà émis meurent seuls (TTL ≤ 900 s) ; fenêtre assumée, la borner est le
   rôle du TTL court.
3. **Les droits des personnes ne sont PAS touchés par défaut** : le droit appartient à la
   personne, pas au programme (« un droit DÉJÀ accordé survit au retrait du programme »).
   Retirer des droits posés frauduleusement = acte staff, tracé, ligne par ligne.
4. Retirer le programme du catalogue si la rupture est définitive
   (`status = RETIRED`, acte owner) — aucun droit existant n'est cascadé.

## 4. Restauration d'une sauvegarde

Renvoi : [SAUVEGARDES.md §4](SAUVEGARDES.md). À relire AVANT le geste :
**toute restauration remonte le temps des registres append-only** — preuves, révocations
et consentements postérieurs au dump cessent d'exister. C'est un acte d'incident majeur
**décidé avec Kevin**, jamais un outil de correction.

**⚠️ Depuis le LOT effacement : une restauration RÉ-INTRODUIT des personnes effacées.**
Tout effacement `COMPLETED` entre la date du dump et l'incident redevient une personne
lisible — sel d'origine, blob, empreintes, profil. Et le registre `person_erasures`
restauré **ne connaît plus ces effacements** : ils ne se « rejoueront » pas seuls.
La liste de contrôle de la restauration gagne donc deux lignes :

1. **AVANT d'écraser quoi que ce soit** : extraire de la base mourante (si elle est
   lisible) les lignes `person_erasures` en `COMPLETED` postérieures à la date du dump —
   à défaut, reconstituer la liste depuis les journaux du worker (`effacement: N
   exécutés`, UUID de demande dans les traces de blocage) ;
2. **APRÈS restauration** : rejouer chaque effacement de cette liste (demande staff +
   exécution — les fonctions de 026/028 sont idempotentes et l'acte est re-tracé).

**Si la liste est irrécupérable, la promesse d'effacement est ROMPUE pour la fenêtre**
(dump → incident) : c'est un incident de données personnelles à part entière — il se
déclare (cas n°1), il ne se tait pas.
