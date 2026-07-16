# User-Core — Cahier des charges (V1.0)

> **Statut : socle fondateur, rédigé AVANT toute ligne de code** — comme pour Payment-Core,
> et pour la même raison : c'est le document qui empêche le service de devenir « le backend
> de la superApp ». Rédigé le 13/07/2026, sur la base de l'inventaire Scolaria
> (`main` = `cce7e712`, production mesurée le 13/07/2026) **vérifié matériellement**
> (6 faits contre-vérifiés fichier:ligne, zéro divergence).

---

## 1. Identité et raison d'être

**User-Core est l'infrastructure de compte et d'identité de l'écosystème** (Scolaria, Mediyo,
CheYo, Zando). **Scolaria en est le premier client, pas l'unique raison.** Ce n'est PAS un
module de Scolaria.

**Le point qui décide de tout** : l'actif business de l'écosystème, ce sont les **COMPTES
PARENTS** — pas Scolaria. La cible est une **superApp** familiale : un catalogue de programmes
qu'une famille active ou désactive. L'enfant finit l'école : Scolaria ne sert plus. **Le compte
parent, lui, reste** — et il sert Mediyo, CheYo, le reste.

User-Core possède donc **trois choses, et trois seulement** :
1. **Le compte** : identité du titulaire, identifiants, secrets, session, MFA, récupération.
2. **Le numéro de téléphone** de l'écosystème : **chiffré, vérifié UNE fois** (preuve de
   possession de ligne), avec sa doctrine du numéro recyclé.
3. **Le catalogue des programmes** activés/désactivés par compte (le cœur de la superApp) —
   un **droit d'accès**, jamais un abonnement.

**Ce qu'il ne saura jamais** : ce qu'un compte *fait* dans un programme. Il sait que le compte
existe et que Scolaria est activé ; il ne sait pas qu'il y a un élève, une classe, une facture.

### Un cœur est d'abord une FRONTIÈRE, pas un déploiement
Six cœurs sont nommés dans l'écosystème ; **un seul est construit** (Payment-Core). User-Core
est le deuxième. La protection ne vient pas d'avoir six serveurs : elle vient de ce que **le
cœur ne connaît jamais son fournisseur ni ses consommateurs**. On extrait un composant quand
une **métrique** le réclame, jamais par anticipation.

### Stack (V1 — sobre, patron Payment-Core)
- **1 service NestJS + TypeScript** · **PostgreSQL** (unique source de vérité) ·
  **transactional outbox** (pas de broker) · Sentry · secrets hors du code (Vault/Infisical).
- **Interdits en V1 sans qu'une métrique les réclame** : RabbitMQ/Kafka, Kubernetes,
  read replicas, tout langage supplémentaire, et toute « flexibilité au cas où ».

---

## 2. La frontière (décision D1 — tranchée le 13/07/2026)

**Règle de test, à appliquer à chaque cas douteux :**
> *« Cette donnée a-t-elle encore un sens si l'enfant a fini ses études et que la famille
> n'utilise plus que Mediyo ? »* — **Oui → User-Core. Non → elle reste dans le programme.**

| ✅ User-Core POSSÈDE | ❌ N'entre JAMAIS |
|---|---|
| Le compte : identité du titulaire, identifiants, secrets | L'élève, la classe, l'école, l'année scolaire → **Scolaria** |
| **Le téléphone (chiffré), vérifié UNE fois** + doctrine du recyclage | Le lien payeur ↔ bénéficiaire du paiement → **Payment-Core** |
| La session, le MFA, la récupération de compte | Les frais, factures, imputations → **Scolaria Finance** |
| **Le catalogue des programmes activés/désactivés** | Les écritures comptables → **Accounting-Core** |
| Les rôles **transverses** (titulaire, staff plateforme, admin plateforme) | Les rôles **métier** (enseignant, directeur, comptable, médecin) |
| Le profil de base (nom, langue, préférences) | L'envoi effectif SMS/WhatsApp/push → **dispatcher** |
| **Les personnes / ayants droit du foyer** (dès la V1 — voir §2.1) | Les conversations → **Plume** · le rendu de documents → **Document-Core** |

### 2.1 Le cas des enfants — tranché : les PERSONNES entrent dès la V1 (arbitrage Kevin, 15/07/2026)
**Décision de Kevin (15/07/2026), amendant la décision verrouillée n°2 :** *« Dès la V1, les
enfants doivent bénéficier de la même liberté au sein de l'écosystème que les autres usagers ;
le faire plus tard coûterait cher. »* Motif : la fenêtre de la production vide est **périssable**
— extraire les personnes quand Scolaria aura des dizaines de milliers d'élèves collés à sa
table interne est un ordre de grandeur plus cher que de le faire maintenant (patron de la
fenêtre, cf. §8). L'auditeur a **vérifié la cohérence** de l'arbitrage et l'a acté.

**La distinction fondatrice que cette décision introduit — PERSONNE ≠ COMPTE :**
- **Une PERSONNE** est une identité humaine (nom, éléments d'état civil), **transverse** :
  la même personne est élève chez Scolaria, demain patiente chez Mediyo — **une seule
  identité, jamais ressaisie**. Possédée par User-Core dès la V1.
- **Un COMPTE** est le *moyen d'agir* (identifiants, secret, session). Il est **rattaché à
  une personne**. Toute personne **autonome** a un compte ; un **enfant mineur n'en a pas
  (encore)** — il est représenté par son/ses responsables.
- **Le lien de responsabilité** : une personne-responsable agit pour une personne-ayant droit.
- **L'ÉMANCIPATION** : à la majorité (ou à un événement défini), l'ayant droit **acquiert son
  compte** — **même `person_id`, identité stable**, nouvelle capacité d'agir. Pas de ressaisie,
  pas de rupture, et **aucun responsable ne garde la main sur la vie d'un majeur**.
- **Les rôles métier restent chez les programmes** (§2 inchangé) : « élève », « patient »
  vivent chez Scolaria et Mediyo et **pointent vers `person_id`**.

**Ce qui reste à concevoir au cadrage du lot « personnes » (ne pas l'inventer avant) :**
le modèle exact `persons` / `accounts` (le cœur du LOT 1 en sera touché — c'est le bon moment,
tout est vide) · **le catalogue s'applique-t-il à une personne ou à un compte** (un enfant
élève est une personne sans compte, dont le responsable gère l'accès) · le flux de rattachement
d'un ayant droit · la mécanique d'émancipation. **Séquencement recommandé par l'auditeur :**
cadrer les personnes **avant de figer l'API publique `/v1`** (LOT 4), pour ne pas publier un
contrat « par compte » qu'on remplace aussitôt par « par personne ».

### 2.2 Deux pièges de frontière, nommés d'avance
1. **Le catalogue de programmes ne devient JAMAIS un moteur d'abonnement.** User-Core dit
   « activé / désactivé ». Si un programme est payant, le paiement vit dans **Payment-Core** ;
   le recouvrement (relances, suspension pour impayé) vivra dans un module de facturation —
   ni ici, ni dans le cœur de paiement. User-Core n'enregistre que le **droit d'accès**.
2. **Seuls les rôles transverses entrent.** *Le jour où User-Core sait ce qu'est un enseignant,
   il sait ce qu'est une école — et il est mort.* Une garde CI (grep des termes de verticales)
   le rend non-négociable (cf. CLAUDE.md).

### 2.3 Frontière avec Payment-Core — le cloisonnement reste inviolable
Un parent qui paie via Scolaria **et** Mediyo restera **deux fiches payeur distinctes** dans
Payment-Core (une par application). **Le lien « c'est la même personne » vit dans User-Core et
n'en sort jamais.** On ne « globalise » jamais le payeur dans Payment-Core : c'est ce qui
garantit que Mediyo ne peut rien voir des paiements Scolaria.

### 2.4 Frontière avec Verification-Core
La **preuve** (possession de ligne, email, KYC, compte bancaire) est un domaine à part entière,
avec sa trace auditable — c'est ce que demandera le régulateur. En V1, la vérification de ligne
vit **derrière une interface** (`LineOwnershipProver`) dans le service User-Core, **comme un
module frontière** : le jour où un deuxième consommateur arrive (Payment-Core pour le KYC
d'une école), elle s'extrait sans réécriture. Le cœur ne connaît jamais le fournisseur d'OTP.

### 2.5 Le dispatcher d'envoi — plomberie, pas cœur, et ZÉRO cycle
L'envoi brut (« ce contenu, à cette adresse, par ce canal ») **ne connaît aucune identité** et
**ne dépend de personne**. Règle de dépendance inviolable :
`Dispatcher ← Verification ← User-Core` · `Dispatcher ← Plume ← User-Core` · **zéro cycle.**
Si l'envoi vivait dans Plume (qui a besoin de User-Core) et que User-Core devait envoyer un
code : cycle, plus rien ne démarre seul. En V1 le dispatcher peut vivre comme simple module ;
son interface est posée **dès le premier jour**.

---

## 3. Construire ou adopter ? (décision D2 — tranchée le 13/07/2026)

**Décision : CONSTRUIRE MINCE, DERRIÈRE UNE COUTURE `AuthenticationProvider` — et ne pas faire
de ce choix une porte à sens unique.** Cinq raisons, toutes vérifiées matériellement sur le
code Scolaria (`cce7e712`) :

1. **Il n'y a rien à débrancher ni à migrer.** Auth 100 % maison (`@nestjs/jwt` + `argon2`,
   9 points de signature vérifiés dans `auth.service.ts`), production quasi vide (~13 lignes
   d'identité au 13/07/2026). Le coût des deux options est aujourd'hui presque nul : **le choix
   n'est pas urgent, la COUTURE l'est.**
2. **Le modèle d'identité est exotique** : identifiant opaque à 10 chiffres (ni email, ni
   téléphone — vérifié `auth.resolver.ts:31/40/78`), téléphone en alias secondaire. Les briques
   du marché sont pensées email/mot de passe/social : les tordre est un combat permanent.
3. **Le filtre qui élimine presque tout le marché** : le numéro de téléphone ne doit **JAMAIS**
   être stocké en clair (discipline Payment-Core). La plupart des briques d'identité le
   stockent en clair — c'est leur fonctionnement normal. Seule une brique acceptant un magasin
   d'utilisateurs branchable / un identifiant opaque resterait candidate.
4. **Le bon patron existe déjà** dans Scolaria : le trio mobile a des sessions **avec état, en
   rotation, avec détection de rejeu (`jti`), fenêtre de grâce 3G, révocables** (vérifié :
   3 tables credentials + migration `20260712150000_refresh_rotation_grace`). Il suffit de
   l'appliquer **aussi au web** — ce qui ferme le trou de sécurité F8.
5. **Ce qu'aucune brique ne donnera, c'est le produit** : la preuve de possession de ligne
   (appel manqué/SMS), le catalogue de programmes, la doctrine du numéro recyclé.

**Garde-fous de la décision :**
- ⚠️ **« Construire mince » ≠ « écrire sa propre cryptographie ».** Bibliothèques éprouvées
  (`argon2`, HMAC/AES du runtime Node) — **jamais** de crypto maison.
- **Ce qui ferait tomber la décision** (à constater, pas à supposer) : une équipe qui ne tient
  pas la discipline crypto/session, ou une surface « ennuyeuse » (gestion des appareils,
  verrouillage, récupération, audit) qui explose. La couture rend alors la bascule vers une
  brique possible **sans réécrire les consommateurs**.

---

## 4. Le modèle de compte (V1)

> ⚠️ **Amendé le 15/07/2026 (personnes dès la V1, §2.1).** Un COMPTE reste le *moyen d'agir* ;
> il est désormais **rattaché à une PERSONNE**. Une personne peut exister **sans** compte
> (enfant mineur). Ce qui suit décrit le compte ; le modèle `persons` / lien de responsabilité
> / émancipation est cadré au lot « personnes ».

- **Un compte = une personne titulaire, unique au niveau de l'écosystème.** Jamais « un compte
  par programme » ni « un compte par école » — c'est précisément le défaut de Scolaria
  (`Parent.schoolId` obligatoire) qu'on ne reconduit pas.
- **Identifiant de connexion** : identifiant opaque (généré), avec **alias téléphone vérifié**
  optionnel. L'email est un alias possible, jamais une obligation (le terrain RDC est
  téléphone-d'abord).
- **Un compte peut exister, naviguer, discuter SANS numéro vérifié** (vérification paresseuse,
  cf. §6.3). Le numéro vérifié n'est requis qu'au moment où le compte veut **payer**.
- **Le compte porte le catalogue** : `(account_id, program, status, granted_at, revoked_at…)`,
  historisé, jamais supprimé physiquement.
- **Rôles transverses uniquement** : `ACCOUNT_HOLDER`, `PLATFORM_STAFF`, `PLATFORM_ADMIN`.
  Tout rôle qui nomme un métier d'une verticale est refusé à la conception.

## 5. Sessions et secrets (V1)

- **Un seul patron de session pour tout le monde** (web ET mobile) : jeton d'accès court +
  **jeton de rafraîchissement avec état** (stocké haché, rotation à chaque usage, détection de
  rejeu, fenêtre de grâce réseau, **révocable serveur**). Le patron asymétrique de Scolaria
  (web auto-suffisant 30 jours, non révocable — trou F8) **n'entre pas** dans User-Core.
- **`logout` serveur obligatoire** dès la V1, et une opération « couper toutes les sessions
  d'un compte » (vol de poste, départ d'un staff).
- Secrets : `argon2id`. Verrouillage progressif sur échecs. Mots de passe provisoires à
  expiration (patron Scolaria conservé).
- **Jamais de code OTP à la connexion de routine** (règle économique ET produit, cf. §6.4).
  Le code sert à l'**amorçage** (première vérification du numéro) et à la **récupération**.

## 6. Le téléphone et la preuve de possession de ligne

### 6.1 Stockage — jamais en clair (patron Payment-Core, décidé maintenant)
- **Empreinte HMAC déterministe** (clé dédiée) : indexée, sert la recherche d'unicité et la
  limitation de débit. **Valeur chiffrée AES-256-GCM** (`key_id` porté par le jeton de
  chiffrement, trousseau rotatif) pour l'affichage masqué et l'envoi.
- ⚠️ **La clé HMAC a un cycle de vie DISTINCT du trousseau de chiffrement** : la tourner
  oblige à déchiffrer et re-hacher toute la PII. Décision posée **avant** la première ligne :
  clé HMAC versionnée (`hmac_key_id` en colonne), rotation = procédure exceptionnelle
  documentée, jamais un réflexe.

### 6.2 Deux besoins que tout le monde confond — la doctrine
| | Ce qu'on veut savoir | Ce qui le prouve |
|---|---|---|
| **Joignabilité** | « Peut-on lui faire parvenir un message ? » | WhatsApp, push, email, SMS |
| **🔒 Possession de la LIGNE** | « La SIM est-elle dans SON téléphone ? Sera-t-elle débitée ? » | **UNIQUEMENT SMS ou APPEL** |

> **Une app ne prouvera jamais la possession d'une ligne. Seul le réseau de l'opérateur le
> peut.** Un compte WhatsApp survit à la carte SIM (résiliée, voire réattribuée à un inconnu).
> Or c'est la SIM qui reçoit la demande de paiement et qui est débitée. **WhatsApp est écarté
> comme preuve de possession** — il reste le canal préféré pour *parler* aux gens.

**Échelle de vérification** (⚠️ **amendée le 16/07/2026** — l'ordre dépend du **VOLUME**, pas
d'un dogme : cf. §6.4) : **appel manqué** (*flash call* — transite par la SIM, marche sur tout
téléphone, imparable au guichet : le parent voit son propre téléphone sonner) · **SMS**
(transite par la SIM : preuve **aussi valable**, et **moins chère au faible volume**) ·
❌ WhatsApp (jamais pour cet usage — raison de **sécurité**, jamais de prix : cette exclusion-là
ne dépend d'aucun tarif) · 🔭 `Silent Network Authentication` / GSMA Open Gateway : la preuve
la plus forte **si** les opérateurs RDC y participent — à vérifier, jamais à présumer.

### 6.3 Vérification PARESSEUSE — le coût suit le revenu
On vérifie le numéro **au premier paiement**, pas à l'inscription. Payment-Core exige déjà un
numéro vérifié avant tout push : la contrainte existe, il suffit de ne pas la déclencher trop
tôt. **Le coût des canaux devient proportionnel au nombre de PAYEURS, pas à la base.**

### 6.4 L'économie des canaux — **chiffres révisés le 16/07/2026** (source Kevin)
⚠️ **Le SMS était estimé à 0,25 $ (12/07). Le chiffre réel est ≈ 0,04 $** — deux sources
convergentes (un fournisseur RDC à 0,041 $ ; DRCNotify à 0,04 $, annonçant des connexions
directes Vodacom/Airtel/Orange/Africell), **probablement proche du prix opérateur** (arbitrage
Kevin). **Facteur 6 par rapport à l'estimation initiale : le calcul est refait, et une règle
est amendée — une règle dont la justification tombe doit être révisée, pas défendue.**

**Le calcul, refait** (école à 500 $/an, 500 parents, facteur de renvoi 1,4 → 700 messages) :

| Usage | Messages/an | Coût | % du revenu de l'école |
|---|---|---|---|
| **Vérifier une fois, au premier paiement** (la règle) | 700 | **28 $** | ✅ **5,6 %** |
| **Un code à chaque connexion** (2×/mois) | 12 000 | **480 $** | 💀 **96 %** |

**Ce qui TIENT, et pourquoi** (aucune de ces règles ne dépendait du prix du SMS) :
- **Jamais de code au login de routine** — 96 % du revenu : ruineux **à tout prix**. La règle
  tient à la **structure**, pas au tarif.
- **Vérification paresseuse** — sa raison est « le coût suit le revenu, pas la base d'inscrits ».
- **Plafond dur par ligne** — sa raison est de **protéger le téléphone d'un TIERS**, jamais
  notre facture.
- **WhatsApp jamais comme preuve** — raison de sécurité (§6.2).

**Ce qui est AMENDÉ** : « SMS = secours rationné » **tombe**. Sa justification était « 35 % du
revenu de l'école » ; à 0,04 $ c'est **5,6 %** — soutenable. **Le SMS n'est pas un pis-aller :
c'est le canal de DÉMARRAGE, le moins cher au faible volume.**

**Le flash call — le chiffre manquant est partiellement obtenu.** Offre CheckMobi (abonnement à
**quota mensuel**, pas du paiement à l'usage) : 15 $/mois → 10 000 vérifications ; 30 $ → 30 000 ;
60 $ → 120 000 (+0,0005 $ au-delà). **À pleine charge : 0,0005 – 0,0015 $ par vérification.**
⚠️ **Le piège du quota** : notre vérification est **unique à vie par parent** — à 42/mois
(1 école), l'abonnement Startup revient à **0,36 $ la vérification**, soit **9× le SMS**.

> **🎯 LE SEUIL DE BASCULE, à graver : ~4 500 vérifications/an** (180 $/an d'abonnement ÷ 0,04 $)
> — soit **≈ 9 écoles** de 500 parents. **En dessous : SMS à l'usage. Au-dessus : flash call**
> (le quota Startup couvre 120 000/an pour 180 $ — **22× moins cher** que le SMS à ce volume).
> **La bascule est un changement de CONFIG, jamais de code** (§3.11 + couture
> `LineOwnershipProver`). C'est précisément pourquoi aucun prix n'a jamais été figé.

**Questions ouvertes AVANT tout contrat** (elles annulent le prix si mal répondues) : le trafic
d'appels courts est-il **accepté** par Vodacom/Orange/Airtel (certains opérateurs le bloquent —
inconnue n°1, §9) ? « *successful verification* » = appel **émis** ou validation **réussie** ?
Le flash call exige-t-il un **SDK** (donc smartphone) ou marche-t-il par **API pure** (donc
téléphone basique, l'utilisateur dicte les 4 chiffres — c'est le cas du guichet) ? Engagement
de durée ? ⚠️ **Un fournisseur voit les numéros en clair : c'est un sous-traitant de données
personnelles** — contrat et garanties exigés (§3.14).

⚠️ **Se méfier des repères du fournisseur** : « les coûts OTP représentent < 0,1 % de la valeur
des transactions » est un ratio **fintech** (revenu = % de transaction). **Notre revenu est un
abonnement école de 500 $/an** — le seul repère valable est le tableau ci-dessus. Et leur guide
recommande explicitement **l'OTP à chaque connexion** : c'est **leur** intérêt commercial, et
**notre ruine** (96 %). *Un fournisseur n'est jamais une source de doctrine.*

### 6.5 Le numéro recyclé — la possession est EXCLUSIVE et au PRÉSENT
Une preuve **fraîche** révoque d'office la revendication antérieure : deux personnes ne
détiennent pas la même SIM au même instant, **la preuve la plus récente gagne, toujours**.
Garde-fous : l'ancien détenteur est prévenu par un **autre** canal · la reprise est **tracée
append-only** · aucune suppression. Risque résiduel assumé : le vol de SIM — on le détecte et
on le ralentit (délais, plafonds), on ne l'élimine pas.

### 6.6 Ce que le dispatcher doit porter (exigences de conception)
Coût de chaque canal **en config** · escalade du moins cher au plus cher, arrêt dès délivrance ·
**plafonds durs** (par type, par jour, global) avec refus d'envoyer + alerte au-delà ·
**journalisation du coût** de chaque message payant (Accounting-Core en aura besoin).
Un bug de boucle ne doit pas pouvoir coûter 10 000 $ dans la nuit.

---

## 7. Les invariants gravés dans PostgreSQL (patron Payment-Core)

Un agent contourne une convention de code, jamais une contrainte Postgres sans laisser une
migration signée. Sont **gravés en base** dès les premières migrations :
- **Unicité mondiale de l'empreinte du numéro vérifié** : au plus UNE revendication ACTIVE par
  ligne (index unique partiel sur `phone_hmac WHERE status = 'ACTIVE'`).
- **Preuves de possession append-only** (trigger + `REVOKE UPDATE, DELETE` du rôle applicatif) ;
  la révocation est une **nouvelle ligne**, jamais une mise à jour destructive.
- **Historique du catalogue append-only** : l'activation/désactivation d'un programme est une
  ligne datée, jamais un UPDATE d'écrasement.
- **Le niveau de preuve ne descend jamais** (contrainte de transition, patron
  `assurance_level` de Payment-Core).
- **Jetons de rafraîchissement hachés** en base (jamais la valeur), avec unicité de `jti`.
- **Aucun terme de verticale** dans le schéma — garde CI bloquante (condition de commit).

## 8. Extraction depuis Scolaria — la méthode

1. **Comptage pré-vol** (2 minutes, agrégats seuls) avant la première étape qui touche aux
   données réelles. Le comptage du 13/07/2026 — ~13 lignes — est **périssable** : chaque famille
   inscrite rapproche le chantier d'une migration de PII, un ordre de grandeur plus cher.
   **Kevin a gelé les ajouts en production le 14/07/2026** (aucun recrutement d'ici la bascule)
   — le pré-vol n'est donc **pas** une renégociation de calendrier, c'est une **vérification**.
   Il reste obligatoire pour une raison qui ne dépend pas du recrutement : **une ligne
   d'identité peut apparaître sans qu'aucune famille ne s'inscrive** — script de rattrapage
   (précédent réel : `backfill-parent-user.ts`, exécuté en production le 04/07/2026), démo,
   compte créé à la main, test joué sur la vraie base. **On ne re-mesure pas parce qu'on doute
   de la parole : on re-mesure parce qu'un script ne demande la permission à personne.**
2. **Jamais de big bang** : extraction progressive, réversible à chaque étape ; Scolaria
   consomme User-Core via une **API publique versionnée**, comme un client externe — aucun
   accès privilégié, sinon l'abstraction multi-verticale meurt à la naissance.
3. **Réconcilier les deux populations de parents** (chemin complet vs chemin d'inscription réel
   sans compte ombre/alias/garde — défaut F5 vérifié) : la réconciliation est une étape du
   plan, pas une surprise.
4. **Le gel Scolaria reste en vigueur** jusqu'à la bascule : aucun ajout sur comptes, auth,
   sessions, profils, vérification — corriger un bug : oui ; ajouter : non.
5. Les ~10 back-relations scolaires de `User` (présences, discipline…) **restent chez
   Scolaria** et pointeront vers une identité devenue externe — c'est LE point de conception
   de l'extraction (v1 : Scolaria garde une table locale de correspondance).

## 9. Les inconnues à obtenir — jamais à inventer

| # | Inconnue | Qui la porte |
|---|---|---|
| 1 | ~~Prix d'un flash call~~ **PARTIELLEMENT OBTENU (16/07/2026)** : offre CheckMobi = abonnement à quota, **0,0005–0,0015 $/vérification à pleine charge** (§6.4). **Restent ouverts, et ils annulent le prix si mal répondus** : l'**acceptation du trafic** d'appels courts par Vodacom/Orange/Airtel · « successful verification » = appel émis ou validation réussie ? · **SDK requis (smartphone) ou API pure (téléphone basique)** ? | Kevin (terrain/contrat) |
| 2 | Silent Network Authentication disponible en RDC (Vodacom/Orange/Airtel) ? | Kevin + recherche |
| 3 | BCC : résidence des données d'identité (régime distinct des données financières ?) | Kevin (BCC) |
| 4 | Proportion de parents payeurs sans WhatsApp (dimensionne le repli SMS) | Kevin (pilote) |

> **⚠️ Reclassement du 15/07/2026 (Kevin) — mineurs & émancipation ne sont PLUS des inconnues
> à obtenir, mais des DÉCISIONS assumées.** Kevin constate qu'**aucun cadre juridique clair
> n'existe en RDC** sur le régime des données d'un mineur, le consentement parental et l'âge
> d'émancipation. La règle devient : **on conçoit comme si un cadre STRICT existait déjà**
> (CLAUDE.md §3.14) — régime volontaire du niveau des standards internationaux, pour ne pas
> être bloqué si la juridiction légifère. Principes de conception retenus (à graver au cadrage
> du lot « personnes ») : **plusieurs responsables** via un lien **historisé** (jamais un
> « parent » figé ; retrait d'un responsable = acte **contrôlé et tracé**) · **émancipation =
> événement explicite**, âge **paramétrable** par défaut, **coupure nette** (aucun ancien
> responsable ne garde d'accès sur un majeur) · **minimisation** (le strict nécessaire à
> l'identité ; date de naissance au minimum utile) · **effacement par crypto-destruction**
> (implication clés-par-personne à concevoir, cf. §3.14).

**Un agent qui code une valeur « supposée » sur l'un de ces points = plan BLOQUÉ.** On
paramètre (config/env), on ne fige pas une hypothèse.

## 10. Décisions verrouillées (ne pas rouvrir sans Kevin)

1. L'actif = les comptes parents ; User-Core survit aux programmes ; jamais « backend de la
   superApp ».
2. Frontière D1 (§2). **Amendé le 15/07/2026 (Kevin) : les PERSONNES / ayants droit du foyer
   entrent dès la V1** (et non en v2) — l'enfant *existe* comme personne de l'écosystème dès
   le départ (identité stable, émancipation en grandissant), sans *agir* seul tant qu'il est
   mineur. Distinction fondatrice PERSONNE ≠ COMPTE, cf. §2.1. La règle « les personnes avant
   Mediyo » demeure — elle est simplement avancée à la V1.
3. D2 : construire mince derrière `AuthenticationProvider` ; bascule vers une brique possible,
   jamais obligatoire ; zéro crypto maison.
4. Téléphone : jamais en clair (HMAC + AES-256-GCM), cycle de vie HMAC distinct, décidé en V1.
5. Possession de ligne : uniquement SMS/appel ; WhatsApp jamais ; preuve fraîche révoque
   l'ancienne ; vérification paresseuse au premier paiement.
6. Jamais de code OTP à la connexion de routine.
7. Un seul patron de session (état + rotation + révocation), web et mobile.
8. Catalogue = droit d'accès, jamais un moteur d'abonnement.
9. Dispatcher sans dépendance ; zéro cycle entre cœurs.
10. Le lien inter-programmes d'une personne vit dans User-Core et n'en sort jamais (pas de
    payeur global dans Payment-Core).
11. PostgreSQL unique source de vérité ; outbox, pas de broker ; invariants en base.
12. Français pour docs + commits ; identifiants de code en anglais.
13. **Concevoir comme si un cadre STRICT de protection des données existait déjà** (Kevin,
    15/07/2026) — régime volontaire du niveau des standards internationaux, minimisation,
    consentement tracé, effacement par crypto-destruction ; cf. CLAUDE.md §3.14. Vaut pour
    toute donnée personnelle, pas seulement les mineurs.
