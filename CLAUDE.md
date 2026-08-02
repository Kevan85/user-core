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
**Motif H — UN SEUL point d'assemblage des trousseaux (LOT prod), périmètre `src/ scripts/` :**
```
git grep -rnE "USER_CORE_[A-Z_]+(_KEYS|_ACTIVE_KEY_ID)" -- src/ scripts/ ':!src/crypto/keyring.ts'
```
Ces motifs doivent retourner **zéro ligne** (hors exemples `metadata`), sinon la CI échoue.
**Ils sont HUIT** — A, B, D, E, F, G, H et l'anti-abonnement de §3.8 — joués par
`tools/check-guards.sh`, et **tous les huit sont des checks REQUIS** de `main` (§4).

⚠️ **Pourquoi le motif F existe** — c'est la leçon la plus dure du dépôt. `phone_hmac` (qui
verrouille la ligne) et `phone_encrypted` (qu'on appellera) peuvent **mentir l'un sur l'autre** :
la base **n'a pas les clés**, elle ne peut donc **pas** tenir cet invariant (c'est délibéré). La
parade — déchiffrer, **re-dériver l'empreinte**, comparer — a été posée au LOT 2… puis **un
deuxième point de déchiffrement est né trois lots plus tard (le publisher) et l'a « oublié » »**,
sans qu'aucun test ne rougisse. **Une discipline ne tient que si elle est mécanique** : tout
déchiffrement passe par le point unique, et la CI refuse qu'un second naisse.

⚠️ **Pourquoi le motif H existe — le motif F, une deuxième fois, sur les CLÉS.** Il y a **quatre
trousseaux à quatre cycles de vie** (chiffrement · empreinte téléphone · codes de possession ·
références d'idempotence des programmes), et un contrôle croisé au démarrage refuse qu'une même
valeur serve deux usages — *y compris deux clés d'un même trousseau, sinon une rotation n'aurait
rien tourné*. **Ce contrôle ne vaut que si TOUT trousseau y passe** : deux des quatre étaient
déjà nés **hors** du point d'assemblage, chacun avec sa copie du parseur, donc hors du contrôle.
C'est le patron exact de la parade P4 « oubliée » par son propre auteur trois lots après sa pose
(leçon ①). `scripts/` est **dans** le périmètre, délibérément : c'est par un script
d'exploitation — une rotation, un backfill — que le second point serait né, exactement comme P4
était rené par le publisher.
📌 **Ce que le motif H ne garde PAS, et qu'il ne faut pas confondre** : il garde l'**assemblage
depuis l'environnement**, pas la **dérivation**. Une clé dérivée d'une clé déjà assemblée
(HKDF + sel par personne, `src/crypto/person-identity.ts`, §8.1) ne lit aucune variable
d'environnement : elle ne le déclenche pas, et c'est correct.

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

⚠️ **Le motif A attrape des mots FRANÇAIS ordinaires — c'est le prix, pas un défaut.** `cart`
vit dans « **cart**e SIM » et « é**cart** » ; `order` vit dans « acc**order** » ; et `tenant` vit
dans « main**tenant** » — celui-là a mordu au LOT effacement, sur la phrase même qui énonce le
choix de Kevin (« ma décision s'applique **maintenant** » → reformulée en « tout de suite »).
**Cinq fois déjà**, la garde a rougi sur de la prose parfaitement légitime. **La réponse est
TOUJOURS de reformuler le commentaire, JAMAIS d'affaiblir le motif** : la forme « évidente »
`\border\b` **laisserait passer `order_id`** — en regex, `_` est un caractère de mot, donc
`order_id` n'a pas de frontière après `order` (vérifié). On perdrait la colonne qu'on voulait
interdire pour gagner le droit d'écrire « accorder ». **Une garde se contourne par la plume,
jamais par le motif.**

✅ **Et la 6ᵉ morsure a enfin démontré l'argument de juillet** : au même lot, le motif a refusé un
**IDENTIFIANT** — la contrainte `chk_..._effective_ordered`, renommée `chk_..._chronology`.
C'était la **première fois** que la garde attrapait du **code** et non de la prose. L'arbitrage de
2026 (« le motif attrape des mots français, on garde la forme large ») était donc juste : la
tolérance sur la prose **achetait** cette prise-là.

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
  équivalent) — **à concevoir au lot « personnes », pas à improviser.** *(Livré au LOT 5 :
  HKDF + sel par personne, cf. §8.1.)*
- ⚠️ **« EFFACÉ » VEUT DIRE « EFFACÉ À J+R »** (LOT prod, étape 6). La crypto-destruction
  n'est **effective** qu'après expiration de la rétention des sauvegardes : tout dump
  antérieur porte encore l'ancien sel, donc la donnée reste techniquement recouvrable tant
  qu'une copie vivante existe. **Et la valeur effective de `R` est le MAXIMUM de TOUTES les
  couches de rétention, jamais celle du script** — snapshots d'hébergeur, versioning et
  corbeille d'un stockage objet (souvent actifs **par défaut**), sauvegarde du serveur de
  sauvegardes, copie manuelle faite un jour pour déboguer. Une seule couche qui dépasse et la
  promesse est fausse. **`R` appartient à Kevin** (§3.11) : on paramètre, et **on lui
  communique la valeur EFFECTIVE, jamais le paramètre.** Détail : `docs/ops/SAUVEGARDES.md`.
- **Protection renforcée du mineur** : consentement parental tracé, et **coupure nette à
  l'émancipation** (aucun ancien responsable ne garde d'accès sur un majeur — cf. CDC §2.1).
- **Résidence des données** : rester capable de localiser la donnée (Postgres unique, pas de
  dispersion) — la réponse BCC (CDC §9) reste ouverte, la conception ne se ferme pas.

Un plan qui détient une donnée personnelle **sans finalité écrite**, ou qui rend l'effacement
d'une personne **impossible par construction**, = **plan REFUSÉ**.

### 3.14bis Les deux murs de l'effacement (démontrés à la source le 30/07/2026)

Le **régime** est verrouillé au CDC §10 n°14 (qui déclenche · le choix immédiat ou 7 jours ·
la notification 48 h · le refus d'effacer un dernier responsable). Ce qui suit n'est pas le
régime : ce sont les deux murs **techniques** sans lesquels il ne tient pas. Ils sont nés d'une
lecture du code existant, pas d'une précaution générale.

**① Une personne effacée n'est PLUS INSCRIPTIBLE — et ce mur vit en base.**
Effacer, ici, c'est détruire le sel dont la clé de la PII est dérivée. Mais le chemin qui permet
de *corriger une faute de frappe dans un nom* (`IdentityService.provide`) re-chiffre sous le sel
**courant** et écrit par un `UPDATE persons` direct, le rôle applicatif détenant
`GRANT UPDATE (civil_identity_encrypted, …)` depuis 014. **Sans mur, le premier usage ordinaire
qui suit un effacement RÉ-IDENTIFIE la personne** — aucun attaquant requis, le logiciel le fait
seul en croyant bien faire. Le cas décisif est l'**adulte en self-service**, dont le compte reste
actif. C'est §3.1 dans sa forme la plus nue (« et la v2 de cet endpoint ? ») et la leçon ④ (une
porte n'arrive jamais avant son mur) : **le mur d'inscription précède ou accompagne la porte
d'effacement, dans le même lot, en base. Un `if` dans un service = plan REFUSÉ.**

**② « EFFACÉ » EST UN ÉTAT QUE LA BASE DÉCLARE — jamais une conclusion tirée d'un échec de
déchiffrement.** Le dépôt possède deux détecteurs d'intégrité qui rendent bruyant, exprès, tout
chiffré qui ne s'ouvre plus : la re-dérivation d'année (`decryptCivilIdentity`) et — bien plus
grave — **la parade P4** (`resolveVerifiedAddress`), celle qui existe pour qu'un message de
l'écosystème n'atteigne jamais un inconnu. **Un effacé n'est pas une corruption** : neutraliser
une empreinte ou re-chiffrer un numéro ferait donc hurler la parade P4 sur des actes
parfaitement légitimes. Le risque n'est pas le bruit, c'est ce que le bruit provoque : **le
prochain auteur assouplira la comparaison pour retrouver le silence** — leçon ⑦ transposée d'une
garde CI à un détecteur. Donc : un **registre d'effacement append-only**, un verdict `ERASED`
**distinct** de `INTEGRITY_VIOLATION` sur TOUS les chemins de lecture, et le principe de la
leçon ⑨ — **on INTERROGE la référence, on ne DEVINE pas l'état en trébuchant dessus.**

📌 **Corollaire d'ordre, vérifié, à trois raisons indépendantes** : on **RÉVOQUE d'abord, on
neutralise ensuite.** (a) une revendication laissée `ACTIVE` sous une clé neutralisée
**bloquerait toute rotation d'empreinte à jamais** (P0115, 025) ; (b) une révoquée n'occupe plus
l'unicité mondiale (index partiel, 006) ; (c) `resolve_notification_address` (009) rend `NULL`
pour toute revendication non `ACTIVE`, **donc la parade P4 n'est jamais atteinte** et ne crie
pas. Le prix à payer est connu : une révoquée est **figée** (P0103, 006), la neutralisation exige
donc une porte contrôlée — jamais une suspension de triggers sur un chemin en ligne (leçon ⑥ :
`scripts/rotate-phone-hmac.ts` a le droit de suspendre parce qu'il est un acte d'exploitation
**service arrêté**, sous l'owner ; un `erase_person()` appelable par le rôle applicatif ne l'a
pas).

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
- Jamais de force-push sur `main`.
- **Les gardes se déclenchent MÉCANIQUEMENT** : `.githooks/pre-commit` joue
  `tools/check-guards.sh` et **refuse le commit** (`core.hooksPath` posé par le `prepare` de
  `package.json`, donc au `npm install` — versionné, il survit aux personnes et aux machines
  neuves). **Jamais `--no-verify` sans accord explicite** — cette règle protège désormais
  quelque chose de réel. *(Elle a longtemps interdit de contourner un hook qui n'existait pas :
  une règle peut garder une porte qu'on n'a jamais posée — cf. §11.)*
- ⚠️ **Jouer le script À LA MAIN ne remplace pas le hook** : `git grep --cached` lit l'**INDEX**.
  Lancé avant `git add`, il valide un contenu qu'il n'a pas lu et répond « tout va bien ». Le
  hook, lui, voit le staging réel. **Une garde jouée sur le mauvais instantané est une garde qui
  ment** — et elle ment dans le sens rassurant, le seul qui soit dangereux.
- **CI = gate de merge, vérifiée À LA SOURCE** (API check-runs sur le SHA exact), jamais sur
  parole. Kevin n'a pas de device de test.
- ⚠️ **Un check qui TOURNE n'est pas un check qui BLOQUE.** La liste des checks *exécutés* et
  celle des checks **requis** (`/branches/main/protection`) sont deux objets distincts : un job
  peut rougir et le merge passer quand même. **Les deux se lisent à la source, jamais dans une
  note ou un prompt** (cf. §11).

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

Voir [docs/CAHIER_DES_CHARGES.md §10](docs/CAHIER_DES_CHARGES.md) — les 13 décisions,
notamment : construire mince derrière couture · téléphone jamais en clair · possession =
SMS/appel uniquement · preuve fraîche gagne · jamais d'OTP de routine · un seul patron de
session · catalogue = droit d'accès · **personnes / ayants droit dès la V1** (amendé le
15/07/2026 — l'enfant existe comme personne de l'écosystème dès le départ, PERSONNE ≠ COMPTE).

### 8.1 Ce que le LOT 5 a gravé (livré le 17/07/2026, migrations `014`→`020`)

La distinction **PERSONNE ≠ COMPTE** n'est plus une intention : elle est **non représentable**
autrement.

- **Le droit d'accès appartient à la PERSONNE, jamais au compte** (« Scolaria pour Junior »,
  pas « la famille a Scolaria »). Raison décisive : **à l'émancipation, il n'y a RIEN à
  transférer.** Un test le rejoue à chaque CI : *le droit d'un mineur survit à la désactivation
  du compte de son responsable.*
- **L'invariant d'émancipation** (P0113), **différé au commit, sur les DEUX tables** : une
  personne ne peut pas à la fois avoir un compte ACTIF et être l'ayant droit d'un lien ACTIF.
  Il rend la coupure non contournable **et tue tous les cycles de responsabilité**, à toute
  longueur — un responsable exige un compte actif, un ayant droit ne peut pas en avoir.
- **La coupure est IRRÉVERSIBLE** : `end_reason = 'EMANCIPATED'` est consulté par le mur ; un
  émancipé ne redevient jamais un ayant droit. *(Sans cela, la protection dépendait de l'écart
  entre l'anniversaire et le 31 décembre.)*
- **Retirer un responsable est un acte STAFF**, en base (`SECURITY DEFINER` + `REVOKE UPDATE`
  **table ET colonne**) — **jamais un self-service** : dans un conflit de garde, le système ne
  tranche pas à la place d'un juge.
- **Émancipation = acte, pas bascule** : seuil **paramétrable** (16 ans), le jeune prouve **SA**
  ligne, avec une **preuve FRAÎCHE** (fenêtre paramétrable — une revendication ancienne ne
  suffit pas), et le compte naît sur le **même `person_id`**.
- **PII de personne** : identité civile chiffrée sous une clé **dérivée HKDF(clé du trousseau,
  sel propre à la personne)** — **effacer une personne = détruire SON sel**, sans toucher aux
  autres ni aux registres. Seule l'**année** de naissance reste en clair (finalité écrite,
  résidu ± 1 an assumé, **le mois n'y entre jamais** : une date fine en clair survivrait à la
  crypto-destruction et ferait de « effaçable » un mensonge).
- ⚠️ **L'effacement n'est PAS livré** — le crochet l'est. `erase_person()`, la **politique de
  rétention des sauvegardes** (sans laquelle *la crypto-destruction est un mensonge*), le
  re-chiffrement des numéros et la neutralisation des empreintes HMAC déterministes sont un
  **lot dédié**, avec trois questions produit/réglementaires **pour Kevin** (à commencer par :
  *qui a le droit de demander l'effacement d'un mineur ?*).

### 8.2 Ce que le LOT prod a gravé (livré le 29/07/2026, migrations `023`→`025`)

Le système est **déployable, pas déployé** (le prover reste le simulateur, la bascule Scolaria
attend). Ce qui est acquis, et qui ne se redémontre plus :

- **Le registre PROUVE l'acteur, il ne le croit plus** (`023`) : **une fonction `SECURITY
  DEFINER` par acteur — le NOM de la fonction EST l'acteur.** Une fonction qui demande l'acteur
  en **argument ne prouve rien** (c'est le défaut qu'on a corrigé : `attach_dependent` a été
  refondue sans son `p_opened_by`). Le rôle applicatif a perdu l'écriture directe des deux
  registres, `REVOKE` posé **table ET colonne**.
  **Critère de périmètre, réutilisable :** *une valeur entre dans ce patron si elle est
  l'**ENTRÉE D'UN INVARIANT**, pas si elle « ressemble » aux autres.* `revoke_reason = 'SELF'`
  alimente le mur de réactivation (« ce que la famille a fermé, elle seule le rouvre ») — donc
  elle entre. `sessions.revoke_reason` décrit un événement qu'aucun mur ne lit — dette nommée
  à part, avec sa **condition de réouverture** écrite dans `023`.
- **Un acte `SELF` exige un compte ACTIF**, muré dans le trigger (pas dans la fonction), et
  **conditionné au seul acteur `SELF`** — une personne sans aucun compte (un mineur) reçoit
  toujours un droit posé par un tiers. Sans ce mur, un compte désactivé posait
  `revoke_reason = 'SELF'` et **verrouillait durablement un programme** contre le programme.
- **La rotation d'empreinte a son MUR AVANT son script** (`025`, `P0115`) : l'unicité mondiale
  porte sur le **COUPLE** `(hmac_key_id, phone_hmac)` — une bascule de référence avant la fin du
  re-hachage laisse coexister **deux revendications ACTIVES sur la même ligne physique**, sans
  qu'aucun index ne rougisse. Le script vient après : une transaction, triggers suspendus et
  réarmés dedans, **refus de courir s'il découvre un trigger qu'il ne connaît pas**, fail-closed
  sur l'intégrité. La **fenêtre d'indisponibilité est structurelle** — elle se planifie.
- **Les murs de production sont le DÉFAUT** : `productionWallsArmed()`, **prédicat unique**.
  Seuls `development` et `test` relâchent ; absent, vide, `staging` ou `produciton` **arment**.
- **Zéro PII chez un tiers** : l'événement Sentry est **reconstruit** en liste blanche (le
  message n'est **jamais** expédié), breadcrumbs morts à trois étages, **espion sur le
  transport** qui compte les envois. Pas de SDK de secrets (ce serait une 4ᵉ couture, §3.9) —
  contrepartie écrite : **toute rotation est un redéploiement**.
- **Un dump + le trousseau HMAC = toute la base.** L'espace des numéros est **énumérable** :
  les deux réunis se cassent par force brute. Jamais au même endroit, dump chiffré au repos,
  et **une clé HMAC retirée n'est pas morte avant J+R**.
- **Cinq runbooks sous `docs/ops/`** (propriété **Exécuteur**), dont : une restauration
  **remonte le temps des registres append-only** — acte d'incident majeur décidé avec Kevin,
  jamais un outil de correction.

### 8.3 Ce que le LOT effacement a gravé (livré le 02/08/2026, migrations `026`→`029`)

Le LOT 5 avait livré **le crochet** ; `014` disait lui-même que « *« effaçable » décrit une
capacité de conception, pas une fonction livrée* ». **Ce n'est plus vrai : la porte existe.** Le
régime est au CDC §10 n°14, les deux murs techniques au §3.14bis ; ici, ce qui ne se redémontre
plus.

- **La crypto-destruction, DEUX gestes, et il faut les deux** : le blob passe à `NULL` (cela
  retire le chiffré des dumps **FUTURS**) **et** le sel est remplacé par un tirage neuf (cela
  rend irrécupérable le chiffré des dumps **PASSÉS**). **Aucun des deux seul ne suffit.**
- **Les murs sont arrivés AVANT la porte, étape par étape** (leçon ④ appliquée au calendrier) :
  P0116 et le registre à l'étape 1, le verdict `ERASED` à l'étape 2, la destruction seulement à
  l'étape 3. Le lot est resté **inerte en production** pendant ses deux premières étapes, exprès.
- **La fenêtre de réflexion VIT** : P0116 n'est armé que sur `COMPLETED`. Un mur qui mordait dès
  la *demande* aurait détruit la rétractation voulue par Kevin — une personne qui perd sa ligne
  pendant la fenêtre n'aurait plus pu revenir en arrière. **Un mur trop large tue ce qu'il garde.**
- **Les deux bouts de la fenêtre sont murés** : rétractation refusée après l'échéance, **et
  exécution refusée avant** — un worker pressé ne détruit pas la réflexion par l'autre bout.
- **Les portes n'ouvrent que la FORME EXACTE de la destruction, sous effacement dû** — et les
  colonnes qu'elles ouvrent sont **hors des `GRANT` de colonne** du rôle applicatif : **deux
  verrous indépendants**, prouvés dans les deux sens.
- **`révoquer → neutraliser` est MURÉ, pas promis** (`COMPLETED` refuse toute revendication
  vivante) — sinon une `ACTIVE` sous clé neutralisée **bloquerait toute rotation à jamais**
  (P0115) et la rotation avorterait sur un message d'intégrité **faux**.
- **Un mur n'est pas une panne** : les compteurs `bloqués` (P0114, attendu) et `en PANNE` sont
  **distincts**, avec contrôle négatif. Un refus métier connu ne doit jamais servir d'abri à un
  incident réel.
- **La liste MONTRÉE = la liste AGIE** (`SKIPPED_ERASED` **tracé**) : un ayant droit effacé
  disparaissait de l'affichage mais recevait quand même son lien — un parent serait devenu le
  responsable légal d'une personne qu'on ne lui a jamais montrée.
- **Le refus du dernier responsable n'a PAS été recodé** : P0114 existait déjà, il a été **testé**
  (leçon ③, 3ᵉ fois). La façade rend le refus **à la demande**, pour qu'un mur différé ne se
  manifeste jamais en panne muette et répétée dans un worker.
- **Ce qui survit est ÉCRIT** (`docs/ops/EFFACEMENT.md` §4) : `birth_year`, `public_identifier`,
  `secret_hash`, `provider_ref` **chez le fournisseur** (couche externe), le graphe familial, et
  **`phone_hmac` dans trois registres append-only** → **le test de présence d'un numéro est BORNÉ,
  PAS FERMÉ**. Un tableau de vérité incomplet est un mensonge poli.
- 📌 **Dette `E-1`, ouverte** : les **droits d'accès restent `ACTIFS`** après effacement — un
  programme qui demande « cette personne a-t-elle accès ? » reçoit **OUI**. Arbitrage Kevin ; point
  de greffe déjà écrit dans l'en-tête d'`erase_person()`.
- ⚠️ **H1 — la SEULE garantie de ce lot qui ne vit pas en base** : l'énoncé d'irréversibilité du
  mode `IMMEDIATE` est porté par l'**interface**. La base ne peut pas vérifier qu'un humain a lu
  une phrase, et un paramètre `p_acknowledged` **ne prouverait rien** (§8.2). Elle est **nommée à
  ses quatre emplacements** — car dans ce dépôt tout invariant vit en base, et **une exception tue
  se lit comme une protection**.
- **9ᵉ garde mécanique** : `.githooks/commit-msg` refuse toute attribution d'outil dans un message
  de commit (§4). Les huit motifs lisent des **chemins** ; aucun ne lisait un **message** — la
  règle tenait sur la relecture, c'est-à-dire sur rien (leçon ①).

## 9. Où est quoi

```
user-core/
├── CLAUDE.md                    ← ce fichier (mode d'emploi des agents)
├── docs/
│   ├── CAHIER_DES_CHARGES.md    ← le quoi/pourquoi complet (V1.0)
│   ├── CONTRAT_D_INTEGRATION.md ← ce qu'un programme peut demander, et ce qui lui est
│   │                               refusé pour toujours (catalogue = liste OUVERTE :
│   │                               un code programme est une DONNÉE, jamais un enum SQL)
│   └── ops/                     ← RUNBOOKS — propriété de l'EXÉCUTEUR (le socle
│       ├── README.md                doctrinal ci-dessus reste à l'Auditeur)
│       ├── SECRETS.md           ← inventaire des 10 secrets, injection sans SDK, murs de boot
│       ├── ROTATION.md          ← une procédure par trousseau ; rotation = redéploiement
│       ├── SAUVEGARDES.md       ← R appartient à Kevin ; « effacé » = « effacé à J+R » ;
│       │                           dump + trousseau HMAC = toute la base
│       ├── DEPLOIEMENT.md       ← migrations PUIS boot ; le service ne migre jamais au démarrage
│       ├── INCIDENT.md          ← fuite de PII, compromission de clé, révocation, restauration
│       │                           (dont : une restauration RÉ-INTRODUIT des effacés)
│       └── EFFACEMENT.md        ← le circuit, les deux compteurs du worker, et le TABLEAU DES
│                                   RÉSIDUS (test de présence BORNÉ, pas fermé ; droits ACTIFS)
└── (code : posé par l'Exécuteur, plan par plan — rien sans validation Auditeur)
```

## 10. Notes finales

- En cas de doute d'architecture : cahier des charges, puis l'Auditeur ; jamais inventer.
- Ce dépôt manipule l'identité de familles et le numéro qui sera débité par les paiements.
  La rigueur du double-check n'est pas une cérémonie : c'est ce qui empêche qu'un inconnu
  reçoive la demande de paiement d'un autre, ou qu'un poste volé garde accès à une école.

---

## 11. Les leçons payées — à relire avant de concevoir une garde

Chacune a coûté un défaut réel. Elles ne sont pas des maximes : ce sont des **erreurs
commises ici**, par l'Exécuteur comme par l'Auditeur, et le prix est déjà payé.

**① Une discipline ne tient que si elle est MÉCANIQUE.** La parade P4 (re-dériver l'empreinte
après déchiffrement) a été posée au LOT 2… puis **oubliée trois lots plus tard par son propre
auteur**, sans qu'aucun test ne rougisse — d'où le motif F. Le corollaire est une **question à
se poser à chaque correction** : *« qu'est-ce qui empêchera ce trou de renaître ailleurs ? »*
Les bonnes réponses sont des gardes CI, des `REVOKE`, des paramètres **obligatoires dans une
signature** (le lecteur ne peut pas *oublier* de comparer). Les mauvaises sont « j'y penserai ».

**② Une garde qui TOURNE n'est pas une garde qui BLOQUE.** Pendant des semaines, tous les
documents affirmaient « `main` est protégé par 8 checks ». L'API en montrait **5** : les gardes
PII, zéro-cycle et P4 — celles qui protègent les leçons les plus chères — **s'exécutaient sans
conditionner le merge**. Personne n'avait regardé, parce que tout le monde *savait*. **Un état
d'infrastructure se lit à la source ou ne se dit pas.** Même famille : une garde jouée sur
l'index au lieu du staging (§4), un `if` de shell qui n'arrête pas un commit, une règle qui
interdit de contourner un hook inexistant.

**③ L'invariant vit dans la base, et « la v2 de cet endpoint » est le test qui tranche.**
Trois fois sur le seul LOT 5, un mur porteur s'est retrouvé dans un service : la coupure
d'émancipation, le « jamais un self-service », la fraîcheur d'une preuve. **Chaque fois, la
donnée nécessaire était DÉJÀ en base** — le mur ne la consultait simplement pas. Le réflexe :
avant d'écrire un `if` de sécurité, chercher ce que le registre sait déjà.

**④ Une porte n'arrive jamais avant son mur.** Livrer un chemin d'écriture une étape avant
l'invariant qui le garde ouvre le trou pour la durée de l'étape. §3.1 appliqué au **temps**.

**⑤ Une justification périmée survit à la règle qu'elle justifiait.** Un commentaire a porté
« SMS ≈ 0,25 $, repli rationné » des mois après que le chiffre réel (0,04 $) eut **annulé la
règle**. Le prochain lecteur aurait conçu contre le CDC. **Quand une décision change, le
commentaire qui la porte change dans le même commit.**

**⑥ Un patron se copie AVEC son défaut.** `emancipation_minimum_age()` a hérité du fail-open de
`active_hmac_key_id()` : en SQL, `'H1' <> NULL` vaut `NULL`, donc le `IF` ne lève pas et **la
garde s'ouvre en silence**. Copier le patron de la maison est le geste correct — **relire ce
qu'on copie l'est aussi**. Toute lecture de référence échoue **FERMÉ** (P0112).

**⑦ Une garde qui efface sa raison d'être se retourne contre elle.** Trois motifs (`class`,
`whatsapp`, puis pays) ont d'abord été écrits dans une forme qui supprimait les commentaires
expliquant *pourquoi* la règle existe. **TESTE TOUJOURS UNE GARDE AVANT DE LA GRAVER** — et
quand elle mord la prose, **reformule la prose** (§3.7).

**⑧ Refuser une consigne AVEC PREUVE est le travail, pas une friction.** Score du chantier au
29/07/2026 : **10 refus/corrections argumentés de l'Exécuteur, fondés 10 fois** — dont un
« piège » de l'Auditeur matériellement faux, un backfill validé qui aurait fabriqué des
identifiants devinables, et une porte validée refusée parce que son mur n'existait pas encore.
**Un agent qui dit « amen » n'apporte rien ; celui qui prouve vaut ce qu'il coûte.**
Symétriquement : **refuser d'affirmer ce qu'on n'a pas vérifié, même quand on a raison** —
l'Exécuteur a livré un rapport en marquant « CI non vérifiée » pendant une panne GitHub, alors
que tout était vert, et il a **déclaré une CI ROUGE** au lieu d'annoncer un vert qu'il n'avait
pas. C'est la règle.
⚠️ **Et ça marche dans les DEUX sens.** Le 10ᵉ refus portait sur l'**Auditeur** : « cette
correction ne casse rien » — c'était faux, 27 fichiers de test cassaient, parce que l'Auditeur
avait raisonné sur `src/` sans regarder `tests/`. **Le bon geste de l'Exécuteur n'a pas été
d'abandonner la correction, mais de constater que l'erreur ne changeait pas la décision et de
faire le travail en plus.** Une erreur de l'auditeur n'annule pas sa consigne : elle annule sa
justification, et il faut alors en chercher une vraie.

**⑨ Vérifier la PRÉSENCE n'est pas vérifier l'ARMEMENT.** Le mur du DSN Sentry (C2) exigeait
que la variable **existe** — pour empêcher un déploiement de partir aveugle. Mais un DSN
illisible fait que le SDK **désactive son transport sans lever** : la variable était là, le mur
passait, et **le service partait aveugle en croyant être surveillé**. Le trou n'avait pas
disparu, il avait **reculé d'un cran**. La parade n'est pas de recopier la règle de validation
du fournisseur (deux définitions divergent toujours — cf. le prédicat unique de §8.2) : c'est
de **lui demander s'il est armé**, après coup. *Le patron de la maison : on interroge la
référence, on ne la reproduit pas* (comme `assertFingerprintKeyAligned` interroge la base).
**Devant toute garde, demander : est-ce que je vérifie que la protection EXISTE, ou qu'elle
FONCTIONNE ?**

**⑩ Le DÉFAUT d'une garde doit être fermé — c'est le mode permissif qui se déclare.**
`if (NODE_ENV !== 'production') return;` ouvrait toutes les protections sur une variable
absente, vide, ou mal orthographiée (`produciton` dans un manifeste suffisait), et la parade
proposée était **une ligne de contrôle dans un runbook** — donc rien (leçon ①). La forme
fermée n'invente aucune détection : elle **inverse la charge**. `productionWallsArmed()` ne
relâche que sur `development` et `test` ; tout le reste arme. **Le pire cas devient un boot
refusé bruyamment sur un poste mal configuré, jamais une production silencieusement nue.**
Corollaire : *si un oubli rend le système plus permissif, la garde est à l'envers.*

**⑪ Une garde peut échouer en ne se LANÇANT pas — la troisième forme de la leçon ②.**
`.githooks/pre-commit` était en mode `100644`. Sous Windows il fonctionnait (git y ignore le bit
d'exécution) et il a **réellement bloqué des commits** ; sur tout clone POSIX, git **ignore un
hook non exécutable** — **les huit gardes ne se seraient jamais lancées au commit**, et seule la
CI aurait rattrapé, c'est-à-dire trop tard pour ce que le hook prévient. §4 affirmait que le hook
« survit aux machines neuves » : la phrase n'était vraie que sur la machine où l'on regardait.
La leçon ② connaissait deux formes — une garde qui **tourne sans bloquer** (les 3 checks non
requis), une garde jouée sur le **mauvais instantané** (`--cached` avant `git add`). En voici une
troisième, et la plus discrète : **une garde qui ne DÉMARRE pas.** Aucun symptôme, aucun message,
et une preuve d'efficacité rassurante sur le poste de celui qui la teste.
⚠️ **Le motif général, à porter au prochain chantier** : *une garde a trois états, pas deux —
absente, présente-mais-inerte, armée. Vérifier la présence ne suffit pas (leçon ⑨) ; vérifier
qu'elle a bloqué UNE fois, ici, ne suffit pas non plus.* Demander : **sur quelle machine, et
qu'est-ce qui la déclenche ?**

**⑫ « Effacé » n'est pas « disparu » — et un tableau de vérité incomplet est un mensonge poli.**
L'en-tête d'`erase_person()` affirmait neutraliser l'empreinte « *— c'est elle qui permettrait de
tester la présence d'un numéro dans un dump* ». Mesuré : le geste ne touche qu'**une** table sur
quatre ; la même empreinte survit dans **trois registres append-only**, laissés intacts
délibérément. La décision était bonne ; **la phrase était fausse, à l'endroit exact où le prochain
auteur irait chercher la vérité.** D'où la règle : **tout lot qui détruit publie la liste de ce
qu'il NE détruit PAS**, et cette liste est exhaustive ou elle ne sert à rien — elle a dû être
complétée deux fois (les registres d'empreintes, puis les **droits d'accès restés ACTIFS**).
