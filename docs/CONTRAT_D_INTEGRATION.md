# User-Core — Contrat d'intégration des programmes (V1.1)

> **Ce document dit ce qu'un programme a le droit de demander à User-Core, et ce qui lui est
> refusé pour toujours.** Il est la contrepartie du cahier des charges : le CDC dit ce que
> User-Core *possède*, celui-ci dit ce qu'il *expose*. Patron : `CONTRAT_VERTICALE.md` de
> Payment-Core. Rédigé le 14/07/2026 · **amendé le 21/07/2026 (V1.1) — les personnes (LOT 5)
> et les opérations métier `/v1` : le droit d'accès porte sur la PERSONNE, pas le compte.**
>
> **La règle qui gouverne tout le reste** : *Scolaria est un client externe comme un autre.*
> Le jour où un programme obtient un privilège « juste pour cette fois », l'abstraction
> multi-verticale est morte — et personne ne s'en apercevra avant Mediyo.

---

## 1. Le seul canal : une API publique versionnée

- Un programme parle à User-Core **uniquement** par l'API publique `/v1/…`. **Aucune lecture
  directe de la base**, aucun accès à un rôle Postgres, aucun script partagé, aucune réplique.
- **Chaque programme a une identité cliente** (`client_id` + secret), un plafond de débit et
  une trace d'appel. Un programme compromis se **révoque** sans toucher aux autres.
- **Versionnement** : aucune rupture de contrat sans une nouvelle version ; une version
  dépréciée est annoncée, jamais éteinte par surprise.
- **Zéro cycle** : User-Core **n'appelle jamais** un programme de manière synchrone. S'il doit
  l'informer (compte désactivé, droit d'accès révoqué), c'est un **événement sortant signé**,
  publié via l'outbox — jamais une dépendance de User-Core vers une verticale.

## 2. Ce qu'un programme PEUT demander — et rien d'autre

> **⚠️ V1.1 — le sujet du droit d'accès est la PERSONNE, jamais le compte.** Un enfant mineur
> **existe** (identité, droit d'accès) **sans agir** (il n'a pas de compte — il est représenté
> par ses responsables). « Scolaria pour Junior », pas « la famille a Scolaria ». **Raison
> décisive : à l'émancipation, il n'y a rien à transférer** — le droit était déjà celui de la
> personne. Là où ce contrat disait « compte » avant le LOT 5, lire « personne ».

| # | Besoin réel | Ce que User-Core rend | API |
|---|---|---|---|
| 1 | « Qui est cet utilisateur ? » | Vérification du **jeton d'accès** par la **clé publique** (EdDSA, `kid` dans l'entête). Le programme **vérifie** un badge ; il ne peut pas en **fabriquer** un. | `/v1/jwks` |
| 2 | « MON programme est-il activé pour cette PERSONNE ? » | Un **oui / non** sur **son** programme, avec la date d'activation — **et seulement le sien** (jamais l'état d'un autre programme). | `/v1/grants/status` |
| 3 | « Comment je la désigne chez moi ? » | Un **identifiant de personne stable** (opaque, dictable au guichet), plus un **profil de base** minimal (nom d'affichage). | (rendu à l'ouverture) |
| 4 | « Ouvrir MON accès pour cette personne » | Un droit d'accès posé sur la **personne** — **si et seulement si le programme est en mode `GRANTED`** (§2.1). Sur une personne **déjà connue** (le programme détient son identifiant), ou en **faisant entrer une famille** (§2.2). | `/v1/grants`, `/v1/dependent-access` |
| 5 | « Consulter / révoquer un accès que J'AI ouvert » | Statut et révocation — **uniquement sur les droits de son propre programme** (prédicat en base, pas une promesse). | `/v1/grants/status`, `/v1/grants/revoke` |

**C'est tout.** Un besoin qui n'entre dans aucune de ces lignes n'est pas une demande
d'intégration : c'est une demande de frontière, et elle se tranche avec l'Auditeur.

### 2.1 Le mode d'accès — une donnée du programme, pas un privilège

Chaque programme du catalogue porte un **mode d'accès** (donnée, jamais du code) :
- **`SELF_SERVICE`** — la personne l'active elle-même, comme on installe une app.
- **`GRANTED`** — un tiers l'ouvre (le programme lui-même, ou le staff) : *l'école inscrit,
  pas le parent.* Un programme en `SELF_SERVICE` **ne peut pas** ouvrir un accès à la place de
  la personne ; un programme en `GRANTED` **ne peut pas** être auto-activé par la famille. La
  base tient les deux sens.

### 2.2 Faire entrer une famille (mode `GRANTED`) — le clic, puis l'invitation

Au **clic** du programme (une inscription), deux choses distinctes se produisent, et l'ordre
est doctrinal :
- **L'accès de l'ayant droit s'ouvre immédiatement** — le droit est sur la personne-enfant, il
  **n'attend pas** le parent.
- **Une invitation part vers le numéro du responsable.** Le **compte du parent naît de l'acte
  du parent** (il pose son propre secret, prouve sa ligne, accepte) — **jamais** créé par le
  programme. C'est ce qui interdit les « deux classes de parents » et protège le compte qui
  paie. Le parent déjà présent (inscrit ailleurs) découvre l'invitation **sans ressaisie**.

**Idempotence :** un re-clic (retry réseau) ne crée **jamais** une deuxième fiche d'enfant, à
condition que le programme joigne **sa propre référence** de requête. Cette référence n'est
stockée **qu'en empreinte** (le cœur est incapable de la lire) : elle est un **verrou
anti-rejeu**, pas une table de correspondance — voir §6.

### 2.3 Pourquoi l'existence d'une personne se confirme, mais pas celle d'un numéro

Deux politiques, **parce que deux situations diffèrent** — ce n'est pas une incohérence :
- **Inviter par un NUMÉRO** ne révèle jamais s'il est connu (`/v1/dependent-access` rend un
  accusé uniforme). Un numéro est un espace **énumérable** que le programme **ne détient pas** :
  répondre « connu/inconnu » serait une machine à énumérer l'écosystème — une fuite sur des
  **tiers**.
- **Agir sur un IDENTIFIANT de personne** (`/v1/grants`) le confirme (un `NOT_FOUND` explicite).
  Un identifiant est **CSPRNG**, opaque, **légitimement détenu** par le programme (rendu à
  l'ouverture, ou dicté au guichet) : ce n'est pas une sonde de découverte, c'est une
  **confirmation d'intégrité** d'une écriture ciblée (détecter la faute de frappe du guichet).
  Il ne révèle que l'existence nue — jamais un nom, un numéro, ni l'accès d'un autre programme.

## 3. Ce qui est REFUSÉ pour toujours

1. **Le numéro de téléphone.** Jamais rendu en clair, à aucun programme, sous aucun prétexte.
   Un programme qui veut faire parvenir un message passe par le **dispatcher** (« ce contenu,
   ce compte, ce canal ») — il n'a **pas besoin** de connaître l'adresse pour l'utiliser.
2. **La liste des programmes d'un compte.** Scolaria demande « Scolaria est-il activé ? » et
   n'obtient **que** cette réponse. **Il ne saura jamais que la famille utilise Mediyo.** C'est
   le même cloisonnement que dans Payment-Core (deux fiches payeur distinctes) : *le lien
   inter-programmes d'une personne vit dans User-Core et n'en sort jamais.*
3. **Ce qu'un compte fait ailleurs** : aucun usage, aucune activité, aucun historique d'un
   autre programme.
4. **Fabriquer un jeton.** Un programme reçoit de quoi **vérifier** (clé publique), jamais de
   quoi **signer**. Sinon n'importe quel programme se forge un badge d'administrateur de la
   plateforme — et ce pouvoir ne se reprend pas.
5. **Un rôle métier.** User-Core ne connaît que `ACCOUNT_HOLDER`, `PLATFORM_STAFF`,
   `PLATFORM_ADMIN`. « Enseignant », « médecin », « bailleur » restent chez le programme, et
   pointent vers l'identifiant de **personne**.
7. **L'accès d'un AUTRE programme sur la même personne.** Un programme ne lit ni ne révoque que
   **ses** droits (`program_id` du jeton = prédicat en base). Il ne saura jamais qu'un autre
   programme a ouvert un accès sur la même personne — même cloisonnement que le point 2.
8. **Le nom d'un ayant droit qu'il n'a pas le droit de voir.** À l'invitation, le nom
   **d'affichage** d'un mineur ne se lit que sous quatre conditions tenues **en base**
   (invitation active, non supprimée, non expirée, **ligne prouvée** de l'appelant) et dans une
   **fenêtre bornée**. Jamais la date de naissance, jamais les composantes du nom, jamais le
   numéro.
6. **Une donnée de verticale**, quelle qu'elle soit — garde CI bloquante (CLAUDE.md §3.7).

## 4. Le catalogue des programmes — **liste OUVERTE** (décision Kevin, 14/07/2026)

Le catalogue **n'énumère pas d'avance** les programmes de l'écosystème. Un programme y entre
**quand il existe vraiment**, pas quand on l'imagine.

**Conséquence de conception, non négociable :** le code d'un programme est une **donnée** (une
ligne de la table des programmes), **jamais un type SQL ni un enum**. Deux raisons :
- un enum obligerait à **une migration par programme** — la liste ouverte deviendrait une
  liste fermée par la porte de derrière ;
- il ferait entrer le **nom d'une verticale dans le schéma** — exactement ce que la garde de
  généricité interdit.

**Et le catalogue reste un DROIT D'ACCÈS** (activé/désactivé, historisé, append-only). Prix,
échéances, relances, suspension pour impayé : **ailleurs** (CDC §3.8). Une colonne `price`,
`billing_cycle` ou `next_renewal` ici = plan REFUSÉ, et une garde CI le refuse déjà.

## 5. La question qui tranche tous les cas douteux

> *« Cette donnée a-t-elle encore un sens si l'enfant a fini ses études et que la famille
> n'utilise plus que Mediyo ? »*
> **Oui → User-Core. Non → elle reste dans le programme.**

Et sa réciproque, pour toute demande d'un programme :
> *« Si j'accorde ça à Scolaria, est-ce que je l'accorderais à Mediyo, à CheYo, et à un
> programme que je ne connais pas encore ? »*
> **Non → ce n'est pas une API, c'est un privilège. Refusé.**

## 6. Ce que le programme garde chez lui

- **Sa table de correspondance locale** (son entité métier ↔ l'identifiant de **personne**
  User-Core) : c'est le point de conception de l'extraction de Scolaria (CDC §8.5). ⚠️ Cette
  correspondance vit **chez le programme, jamais chez nous.** La *référence d'idempotence* que
  User-Core stocke (§2.2) n'est **pas** cette table : elle n'existe qu'en **empreinte**
  illisible, elle sert un seul but — reconnaître un re-clic — et ne dit **rien** de l'entité
  métier qu'elle désigne.
- **Ses rôles métier, ses données métier, ses écrans.** User-Core ne saura jamais qu'il existe
  une classe, une ordonnance ou un loyer — et c'est précisément ce qui lui permet de tous les
  servir.
- **Le consentement au traitement de SES données.** User-Core enregistre un **droit d'accès**,
  pas un traitement. 📌 *Question produit ouverte (Kevin)* : dans le régime strict de protection
  des données (CDC §3.14), une ouverture d'accès `GRANTED` directe sur un mineur doit-elle
  laisser une **trace de consentement** du responsable chez User-Core, ou la confiance accordée
  au programme (mode `GRANTED`) suffit-elle ? À trancher avant Mediyo.
