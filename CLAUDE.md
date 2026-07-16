# Claude Code — Guide de Collaboration (User-Core)

> Lis ce fichier **en entier** au début de chaque session, ainsi que
> [docs/CAHIER_DES_CHARGES.md](docs/CAHIER_DES_CHARGES.md) (le quoi/pourquoi). Les règles
> ci-dessous sont **non négociables** : elles régissent la manière dont les agents
> travaillent sur ce repo. En cas de conflit avec un comportement par défaut, **ce fichier
> prime**.

---

## 0. Identité du dépôt

**User-Core** est l'**infrastructure de compte et d'identité** de l'écosystème (Scolaria,
Mediyo, CheYo, Zando). **Scolaria en est le premier client, pas l'unique raison.** Ce n'est
PAS un module de Scolaria.

- L'actif business = **les comptes parents**. Le compte survit aux programmes : l'enfant finit
  l'école, le compte reste.
- User-Core possède : **le compte** (identifiants, secrets, session, MFA, récupération), **le
  téléphone chiffré vérifié une fois**, **le catalogue des programmes** (droit d'accès), et —
  **depuis l'arbitrage Kevin du 15/07/2026** — **les PERSONNES / ayants droit du foyer dès la
  V1** (distinction fondatrice PERSONNE ≠ COMPTE : l'enfant *existe* sans *agir* seul ; cf.
  CDC §2.1).
- Public : RDC, réseau instable, téléphone-d'abord (pas d'email), WhatsApp dominant, SMS cher.

### Stack (V1 — sobre)
- **1 service NestJS + TypeScript** · **PostgreSQL** (unique source de vérité) ·
  **transactional outbox** (pas de broker) · Sentry · secrets via Vault/Infisical.
- **Interdits en V1 sans qu'une métrique les réclame** : RabbitMQ/Kafka, Kubernetes,
  PgBouncer, read replicas, tout langage supplémentaire.

---

## 1. Méthodologie dual-session Auditeur / Exécuteur

Identique à Payment-Core, elle a fait ses preuves (11 défauts sérieux attrapés) :

- **Auditeur** (lecture seule sur le **code**) : vérifie **matériellement** les rapports,
  valide/refuse les plans, tranche la technique, rédige les PR. **Propriétaire exclusif de la
  mémoire et du socle documentaire** (CDC, ce fichier, README) — il les commite lui-même sur
  une branche docs isolée ; l'Exécuteur ne les touche jamais.
- **Exécuteur** (seul à écrire le **code** + son git) : présente un **plan numéroté** AVANT
  d'agir, attend « VALIDÉ — Go étape N », rend un **rapport structuré** après chaque étape
  (branche, SHA, fichiers, DoD, tests, **verdict explicite de CHAQUE consigne reçue** :
  ✅ appliquée / ⚠️ non appliquée et pourquoi).
- **Kevin est fondateur NON-DEV.** Il relaie et tranche la **valeur produit / métier /
  réglementaire**. On ne lui demande JAMAIS un choix technique ; on ne lui affirme JAMAIS un
  fait de marché (tarifs, usages, réglementation RDC : c'est LUI la source).

Format des réponses de l'Auditeur : deux blocs — **« 📨 À TRANSMETTRE À L'EXÉCUTEUR »**
(copiable verbatim : Go/corrections numérotées, preuves fichier:ligne, tests exigés) +
**« 💬 Message Kevin »** (vulgarisé non-dev, chemins absolus, jamais de jargon non expliqué).

**Calibrage de la sévérité** (un auditeur qui crie au loup perd le pouvoir de signaler un
vrai incendie) : 🔴 = sécurité, argent ou intégrité d'un registre en jeu **et c'est DÉMONTRÉ**
(fichier:ligne, scénario reproductible) · 🟠 = défaut réel, conséquence bornée · 📌 =
arbitrage/note/dette. Un coût ou un fait de marché n'est JAMAIS 🔴 sans calcul posé. « J'ai
cherché, il n'y a rien » est une réponse valable et attendue.

🔴 **Liste noire git de l'Auditeur** — le répertoire principal est LE POSTE DE TRAVAIL DE
L'EXÉCUTEUR. L'Auditeur n'y modifie JAMAIS le HEAD ni le disque : `checkout` (même avec
`-- <pathspec>`), `switch`, `restore`, `pull`, `merge`, `rebase`, `reset`, `stash`, `clean`,
`apply` sont INTERDITS. Tout s'inspecte sans toucher le disque : `git show <ref>:<chemin>` ·
`git grep <motif> <ref>` · `git diff` · `git log` · `fetch` (sûr) — jamais `pull`.

## 2. Contrat de double-check (RÈGLE INVIOLABLE)

L'Auditeur peut se tromper. L'Exécuteur aussi. **AVANT de valider un plan/rapport, on vérifie
MATÉRIELLEMENT** (lecture fichier:ligne, `git show`, `git grep`) ce que l'autre affirme. Ses
propres diagnostics sont des **hypothèses à re-vérifier**. **L'un des deux DOIT capter l'erreur
de l'autre. JAMAIS d'« amen » sans preuve fichier:ligne.** Un Exécuteur qui refuse une consigne
de l'Auditeur **avec preuve** fait exactement son travail.

---

## 3. Règles inviolables spécifiques à l'identité

### 3.1 Les invariants vivent dans PostgreSQL, PAS seulement dans le code
Triggers, `CHECK`, index uniques **partiels**, FK composites, colonnes `GENERATED`, `REVOKE`
de rôle. **Le patron : rendre l'erreur NON-REPRÉSENTABLE.** Une garde applicative que le
prochain chemin d'appel oubliera = **plan REFUSÉ**. (C'est exactement le défaut qui a produit
les « deux classes de parents » de Scolaria : une garde posée dans UN chemin de création,
absente de l'autre.) Gravés en base dès les premières migrations :
- au plus **UNE revendication ACTIVE par ligne téléphonique** (unique partiel sur l'empreinte) ;
- **preuves de possession et historique du catalogue append-only** (trigger + `REVOKE
  UPDATE, DELETE`) ;
- le **niveau de preuve ne descend jamais** ;
- jetons de rafraîchissement **hachés**, `jti` unique.

**Le test qui tranche, à s'appliquer à SOI (Auditeur compris) :**
> **Une API est par nature du code applicatif. La tentation sera de valider dans le code ce que
> la base devrait refuser. L'API valide pour rendre une erreur PROPRE — jamais pour PROTÉGER
> l'invariant.**

Devant chaque garde proposée, une seule question : *« si un autre chemin d'appel écrit
directement en base — un job, un script, un endpoint d'admin, la v2 de cet endpoint — que
se passe-t-il ? »* Si la réponse est « l'invariant tombe », la garde est **au mauvais étage**.
La validation applicative reste **utile et attendue** (un `400` explicite vaut mieux qu'une
violation de contrainte brute remontée au client) — mais elle est la **façade**, jamais le mur
porteur. Un plan dont le mur porteur est un `if` = **plan REFUSÉ**.

### 3.2 ZÉRO PII en clair — le téléphone d'abord
**Le numéro de téléphone n'existe JAMAIS en clair en base ni en log.** Patron Payment-Core :
**empreinte HMAC déterministe** (indexée) + **valeur AES-256-GCM** (`key_id`, trousseau
rotatif). La clé HMAC est **versionnée dès le premier jour** (`hmac_key_id`) et son cycle de
vie est **distinct** du trousseau de chiffrement. Logs = counts, UUID techniques, enums,
`err.name`. Jamais un numéro, un nom, un secret, un jeton, un payload déchiffré.

### 3.3 Possession de ligne : UNIQUEMENT SMS ou APPEL — jamais WhatsApp
Un compte WhatsApp **survit à la carte SIM**. Seul un canal qui transite par la SIM (SMS,
appel) prouve la possession — et c'est la SIM qui sera débitée par le paiement. WhatsApp reste
un canal de **joignabilité**, jamais de **preuve**. **Un agent qui propose de « vérifier le
numéro par WhatsApp » = plan REFUSÉ.**

### 3.4 La preuve la plus récente gagne, toujours (numéro recyclé)
La possession d'une ligne est **exclusive et au présent**. Une preuve fraîche **révoque
d'office** la revendication antérieure ; l'ancien détenteur est prévenu par un **autre**
canal ; tout est tracé append-only. Un flux qui refuse le nouveau détenteur parce que « le
numéro est déjà pris » = défaut de conception.

### 3.5 JAMAIS de code OTP à la connexion de routine
Le code sert à l'**amorçage** (première vérification) et à la **récupération de compte**.
Ensuite : mot de passe/PIN + session longue durée. « Un code à chaque login, c'est plus sûr »
= destruction de marge déguisée en prudence. **Calcul refait au prix RÉEL du SMS (≈ 0,04 $,
révisé le 16/07/2026 — l'estimation initiale de 0,25 $ était fausse d'un facteur 6, CDC §6.4) :
un code à chaque connexion = 480 $/an pour une école qui en paie 500 = 96 % de son revenu.
La règle tient donc à la STRUCTURE, pas au tarif** — c'est ce qui la rend non négociable.
⚠️ Le fournisseur de SMS, lui, **recommande** l'OTP à chaque connexion : c'est son intérêt
commercial. **Un fournisseur n'est jamais une source de doctrine.**
De même : **vérification PARESSEUSE** — le numéro se vérifie au **premier paiement**, pas à
l'inscription.

### 3.6 Un seul patron de session — avec état, révocable
Jeton d'accès court + refresh **avec état** (haché en base, rotation, détection de rejeu,
fenêtre de grâce réseau, révocable serveur), **pour le web COMME pour le mobile**. `logout`
serveur et « couper toutes les sessions du compte » existent dès la V1. Un jeton
auto-suffisant longue durée non révocable (le trou F8 de Scolaria) = **plan REFUSÉ**.

### 3.7 Le cœur reste générique — garde CI bloquante (motifs contractuels)
Aucune colonne, aucun type, aucun identifiant ne porte un concept d'une verticale. La règle ne
dépend de la vigilance de personne : elle est une **garde CI bloquante dès le premier commit**
(sur Payment-Core, la même garde a déjà bloqué l'Exécuteur ET l'Auditeur).

**Motif A — périmètre `db/ src/ scripts/`, sensible à la casse :**
```
git grep -rnE "student|pupil|teacher|school|academic|patient|doctor|clinic|property|tenant|order|cart|enrollment|classroom|classId|class_id|\bfee\b|\bfees\b" -- db/ src/ scripts/
```
**Motif B — le terme `class` seul, périmètre `db/` UNIQUEMENT :**
```
git grep -rnE "(^|[^_])class" -- db/
```
**Motif D — PII et canal de preuve (LOT 2), périmètre `db/ src/`, SENSIBLE à la casse :**
```
git grep -rnE "phone_plain|phoneNumber|msisdn|WHATSAPP|whatsapp|whats_app" -- db/ src/
```
**Motif E — zéro cycle (LOT 3), périmètre `src/dispatch/` :** le dispatcher ne connaît **aucune
identité** et ne dépend de personne (CDC §2.5).
```
git grep -rnE "account|phone|claim|session|from '\.\./(auth|phone|catalog|outbox|accounts)" -- src/dispatch/
```
**Motif F — UN SEUL point de déchiffrement (LOT 3) :**
```
git grep -rn "decrypt(" -- src/ ':!src/crypto/' ':!src/phone/verified-address.ts'
```
Ces motifs doivent retourner **zéro ligne** (hors exemples `metadata`), sinon la CI échoue.

⚠️ **Pourquoi le motif F existe** — c'est la leçon la plus dure du dépôt. `phone_hmac` (qui
verrouille la ligne) et `phone_encrypted` (qu'on appellera) peuvent **mentir l'un sur l'autre** :
la base **n'a pas les clés**, elle ne peut donc **pas** tenir cet invariant (c'est délibéré). La
parade — déchiffrer, **re-dériver l'empreinte**, comparer — a été posée au LOT 2… puis **un
deuxième point de déchiffrement est né trois lots plus tard (le publisher) et l'a « oublié » »**,
sans qu'aucun test ne rougisse. **Une discipline ne tient que si elle est mécanique** : tout
déchiffrement passe par le point unique, et la CI refuse qu'un second naisse.

⚠️ **Pourquoi le motif D est sensible à la casse** (arbitrage tranché le 14/07/2026, contre la
forme d'abord demandée par l'Auditeur — l'Exécuteur a refusé **avec preuve**, et il avait
raison) : la forme insensible à la casse ne matchait **que des commentaires de doctrine** —
ceux qui expliquent *pourquoi* un compte WhatsApp survit à la SIM et ne prouve donc **rien**.
Elle aurait obligé à **effacer la raison d'être de la règle qu'elle protège**. La forme retenue
attrape toutes les formes de **code** (`WHATSAPP` en valeur d'enum, `whatsapp` en identifiant,
`whats_app` en colonne) et laisse vivre la **prose**. **Une garde qui supprime son propre
« pourquoi » se retourne contre elle.**
Le jour où le dispatcher aura besoin de WhatsApp comme canal de **joignabilité** (jamais de
**preuve** — §3.3), c'est **l'Auditeur** qui amendera ce motif, jamais l'Exécuteur de sa propre
initiative.

⚠️ **Pourquoi deux motifs, et pourquoi `class` est exclu de `src/`** (vérifié matériellement,
14/07/2026) : `class` est un **mot-clé du langage**. Sur `payment-core/src`, le motif nu `class`
matche **18 fichiers** (`export class AppModule`, `export class CryptoConfigError`…) — la garde
échouerait sur le premier commit NestJS et serait désarmée dans la semaine. Le schéma vit dans
`db/` : c'est là que « classe scolaire » doit être **non représentable**, et le SQL n'a pas de
mot-clé `class`. Le préfixe `[^_]` laisse passer `pg_class` (catalogue Postgres), jamais
`class_id`.

**Deux contraintes que cette garde impose au code** (elles se paient une fois, elles ne se
discutent pas) : les mots-clés SQL s'écrivent en **MAJUSCULES** (`ORDER BY`, jamais `order by`
— la garde est sensible à la casse) et aucun identifiant `orderBy` n'entre dans `src/`.
`tests/` est **hors périmètre** : les tests d'invariants doivent pouvoir interroger
`pg_catalog` / `pg_class`, et ils ne définissent aucun schéma.

Les rôles sont transverses (`ACCOUNT_HOLDER`, `PLATFORM_STAFF`, `PLATFORM_ADMIN`) : le jour où
User-Core sait ce qu'est un enseignant, il est mort.

**Motif G — le cœur est agnostique du PAYS comme du MÉTIER** (règle jumelle, posée le
16/07/2026), périmètre `db/ src/`, **SENSIBLE à la casse** :
```
git grep -rnE "post_nom|postNom|postnom|POST_NOM|\+243" -- db/ src/
```
⚠️ **Pourquoi sensible à la casse, et pourquoi ni `RDC` ni `congo` n'y figurent** — **la même
leçon, pour la TROISIÈME fois** (après `class`, puis `whatsapp`) : la première forme de ce motif
était `-niE "…|\bRDC\b|congo"`. **Testée avant d'être gravée, elle matchait 8 lignes — toutes des
commentaires de doctrine** (`SMS ≈ 0,04 $ en RDC` · `réseau instable — le cas le plus banal en
RDC` · `l'espace des numéros congolais` · `inconnue de terrain, disponibilité en RDC`). Elle
aurait **effacé le contexte de terrain qui justifie les règles**. Le motif retenu vise les formes
de **CODE** (`post_nom` en colonne, `postNom` en identifiant, `+243` en préfixe câblé) et laisse
vivre la **prose** (« post-nom » avec tiret, « RDC », « congolais »). **Une garde qui supprime
son propre « pourquoi » se retourne contre elle** — et cette leçon a maintenant coûté trois
tentatives : **teste toujours une garde AVANT de la graver.**

⚠️ **Pourquoi cette règle existe.** En RDC, un nom s'écrit **Nom + Post-nom + Prénom** (fait de terrain, source
Kevin). La tentation est d'ajouter une colonne `post_nom`. **Le jour où le schéma dit
`post_nom`, User-Core est congolais — et il ne servira jamais le Congo-Brazzaville**, qui n'a
pas de post-nom : migration, colonnes vides qui mentent, `si pays = X alors…`. C'est exactement
le défaut « école » transposé à la géographie. **La règle jumelle de « le jour où User-Core sait
ce qu'est un enseignant, il est mort » est : « le jour où il sait ce qu'est un post-nom, il est
congolais ».**
**Ce qu'on fait à la place** : des **composantes de nom génériques** (le post-nom congolais est
une *composante additionnelle* — le même emplacement que le *middle name* américain, le
deuxième prénom français, le deuxième nom de famille espagnol) + un **nom d'affichage FOURNI**.
**User-Core STOCKE, il n'INTERPRÈTE pas** : il ne décide pas comment un Congolais s'appelle, ni
dans quel ordre, ni laquelle de ses composantes est « le vrai nom ». **Chaque programme applique
SA convention locale.** Brazzaville = une composante de moins, **zéro migration**.
*(Exemple concret : « en RDC, forte culture du nom — on dit “Bonjour Kabeya”, pas “Bonjour
Junior” ». C'est vrai, c'est utile — et ça vit dans **l'application**, qui pré-remplit le nom
d'affichage. Jamais dans le cœur : sinon Brazzaville, ou un parent qui préfère son prénom,
exigeraient une migration. Et Kevin l'a donné comme « fortement probable », pas certain — une
hypothèse ne se grave jamais dans un schéma, §3.11.)*

### 3.8 Le catalogue n'est PAS un moteur d'abonnement
User-Core enregistre le **droit d'accès** (activé/désactivé, historisé). Prix, échéances,
relances, suspension pour impayé : **ailleurs** (Payment-Core + futur module de facturation).
Une colonne `price`, `billing_cycle`, `next_renewal` dans le catalogue = **plan REFUSÉ**.

Comme en §3.7, la règle est **gravée en CI** (patron `garde-wallet` de Payment-Core) —
périmètre `db/ src/ scripts/`, insensible à la casse, zéro ligne attendue :
```
git grep -rniE "price|billing_cycle|next_renewal|subscription|invoice|\bamount\b|currency" -- db/ src/ scripts/
```

### 3.9 Exactement trois coutures réversibles
1. **`AuthenticationProvider`** — le maison derrière, une brique branchable plus tard.
2. **`LineOwnershipProver`** — simulateur, puis flash call / SMS / SNA ; jamais un fournisseur
   d'OTP câblé en dur.
3. **`OutboundDispatcher`** — « ce contenu, cette adresse, ce canal » ; il ne connaît AUCUNE
   identité et ne dépend de personne (zéro cycle entre cœurs).
**Toute quatrième « flexibilité au cas où » est refusée.**

### 3.10 Zéro suppression physique
Compte, preuve, session, entrée de catalogue : on corrige par statut, révocation, nouvelle
ligne **auditables**. Jamais de `DELETE`. (La désactivation d'un compte est un statut ; le
droit à l'effacement, s'il devient une exigence légale RDC, se traite par une procédure
dédiée décidée avec Kevin — jamais par un `DELETE` de réflexe.)

### 3.11 Les inconnues de terrain ne s'INVENTENT pas
Prix du flash call en RDC, disponibilité de la Silent Network Authentication, résidence des
données d'identité (BCC), proportion de payeurs sans WhatsApp : **inconnues à obtenir, pas à
deviner** (CDC §9). **Un agent qui code une valeur supposée = plan BLOQUÉ.** On paramètre, on
ne fige pas.

### 3.12 L'outbox est un mécanisme de fiabilité, JAMAIS un broker maison
Écrite dans la transaction, drainée par UN publisher, `PENDING/PUBLISHED` + retry basique.
Offsets multi-consommateurs, topics/routing, replay sélectif, rétention, dead-letter par
consommateur : **interdits** — leur besoin est le signal d'introduire un vrai broker, pas
d'enrichir l'outbox.

### 3.13 Aucun appel réseau sous transaction ouverte
On réserve, on commit, on appelle (fournisseur de vérification, dispatcher), on écrit le
verdict dans une transaction neuve.

### 3.14 Concevoir comme si un cadre strict de protection des données existait déjà
**Décision fondatrice de Kevin (15/07/2026) :** *« Faisons comme si un cadre juridique strict
existait, afin de ne pas être bloqués si la juridiction légifère. »* Il n'existe **pas** de
cadre clair en RDC (fait de terrain, source Kevin) — on adopte donc **volontairement** un
régime du niveau des standards internationaux. **« Pas de loi aujourd'hui » ≠ « aucun risque
demain »** : un partenaire santé, un bailleur, un opérateur peut l'exiger avant Mediyo. Vaut
pour **toute** donnée personnelle (numéro, nom, date de naissance, consentement), pas seulement
les mineurs.

- **Minimisation & finalité** : chaque donnée personnelle a une finalité écrite. Rien « au cas
  où ». (Déjà tenu par la frontière : le scolaire/santé reste chez les programmes.)
- **Consentement tracé** : append-only, horodaté — surtout le consentement d'un responsable
  pour un mineur.
- **Droit à l'effacement, SANS casser l'intégrité append-only** (§3.10) — la tension se résout
  par le chiffrement : la PII est chiffrée, **effacer = détruire la clé** (donnée illisible à
  jamais, registres techniques intacts). ⚠️ **Implication non résolue** : le trousseau actuel
  (LOT 2) chiffre tout sous une clé partagée → l'effacement est « tout ou rien ». Effacer **une
  personne** exigera une **granularité de clé par personne** (dérivation + sel oubliable, ou
  équivalent) — **à concevoir au lot « personnes », pas à improviser.**
- **Protection renforcée du mineur** : consentement parental tracé, et **coupure nette à
  l'émancipation** (aucun ancien responsable ne garde d'accès sur un majeur — cf. CDC §2.1).
- **Résidence des données** : rester capable de localiser la donnée (Postgres unique, pas de
  dispersion) — la réponse BCC (CDC §9) reste ouverte, la conception ne se ferme pas.

Un plan qui détient une donnée personnelle **sans finalité écrite**, ou qui rend l'effacement
d'une personne **impossible par construction**, = **plan REFUSÉ**.

---

## 4. Git Workflow

- Une feature = une branche depuis `main` à jour (`feat/`, `fix/`, `chore/`), worktree isolé
  si sessions parallèles.
- `git add` **PAR FICHIER** (jamais `-A` ni `.`). `git status` avant chaque commit.
- Commits conventionnels en **français** (scope anglais toléré).
- **ZÉRO mention d'un outil d'IA** dans les commits, PR, code ou docs. Le projet est attribué
  à Kevin.
- Merge via **PR GitHub** (« Create a merge commit », PAS squash/rebase). L'Auditeur rédige
  titre + body ; l'Exécuteur utilise le bloc verbatim.
- **Clean-clean** après merge : branches locale + distante supprimées, `ls-remote` vide,
  worktree retiré, `prune`.
- Jamais de force-push sur `main`. Jamais `--no-verify` sans accord explicite.
- **CI = gate de merge, vérifiée À LA SOURCE** (API check-runs sur le SHA exact), jamais sur
  parole. Kevin n'a pas de device de test.

## 5. Qualité du code & tests

- **Tests obligatoires**, gate de merge : machines d'état de session, invariants Postgres
  (sous le **rôle applicatif bridé**, hors transaction de test — un test en BEGIN/ROLLBACK ne
  prouve JAMAIS un trigger DEFERRED), idempotence, et le **simulateur qui ment** (un
  fournisseur de vérification qui ne rejoue que le chemin heureux ne prouve rien).
- **Pièges connus** : `sum(...) = 0` passe aussi sur zéro ligne → assert le **nombre de
  lignes ET la somme** ; pour prouver une **absence** (aucun SMS envoyé, aucun appel émis),
  **compte les appels** (espion), pas les résultats.
- Modularité : 1 fichier = 1 responsabilité. Migrations SQL versionnées, testées, jamais
  destructives.
- Aucun secret en dur ; aucun secret prod sur un poste dev.

## 6. Sécurité

- **BOLA systématique** (contrôle d'accès au niveau objet) — un compte ne lit que lui-même.
- Rate-limit sur toutes les mutations d'authentification et d'envoi de code ; plafonds durs
  de coût sur le dispatcher (refus + alerte au-delà).
- Séparation stricte dev / staging / prod. **Jamais de données de test vers la prod.**

## 7. Frontières (inviolables)

- **Scolaria (et tout programme) est un client externe comme un autre** : API publique
  versionnée, aucun accès privilégié, aucune lecture directe de la base de User-Core.
- User-Core ne sait jamais ce qu'un compte **fait** dans un programme ; il sait qu'un
  programme est activé, point.
- **Le lien inter-programmes d'une personne ne sort JAMAIS de User-Core** (pas de payeur
  global dans Payment-Core).
- Règle de test à chaque cas douteux : *« cette donnée a-t-elle encore un sens si la famille
  n'utilise plus que Mediyo ? »* Non → elle n'entre pas.

## 8. Décisions verrouillées (ne pas rouvrir sans Kevin)

Voir [docs/CAHIER_DES_CHARGES.md §10](docs/CAHIER_DES_CHARGES.md) — les 12 décisions,
notamment : construire mince derrière couture · téléphone jamais en clair · possession =
SMS/appel uniquement · preuve fraîche gagne · jamais d'OTP de routine · un seul patron de
session · catalogue = droit d'accès · **personnes / ayants droit dès la V1** (amendé le
15/07/2026 — l'enfant existe comme personne de l'écosystème dès le départ, PERSONNE ≠ COMPTE).

## 9. Où est quoi

```
user-core/
├── CLAUDE.md                    ← ce fichier (mode d'emploi des agents)
├── docs/
│   ├── CAHIER_DES_CHARGES.md    ← le quoi/pourquoi complet (V1.0)
│   └── CONTRAT_D_INTEGRATION.md ← ce qu'un programme peut demander, et ce qui lui est
│                                   refusé pour toujours (catalogue = liste OUVERTE :
│                                   un code programme est une DONNÉE, jamais un enum SQL)
└── (code : posé par l'Exécuteur, plan par plan — rien sans validation Auditeur)
```

## 10. Notes finales

- En cas de doute d'architecture : cahier des charges, puis l'Auditeur ; jamais inventer.
- Ce dépôt manipule l'identité de familles et le numéro qui sera débité par les paiements.
  La rigueur du double-check n'est pas une cérémonie : c'est ce qui empêche qu'un inconnu
  reçoive la demande de paiement d'un autre, ou qu'un poste volé garde accès à une école.
