# User-Core — Contrat d'intégration des programmes (V1.0)

> **Ce document dit ce qu'un programme a le droit de demander à User-Core, et ce qui lui est
> refusé pour toujours.** Il est la contrepartie du cahier des charges : le CDC dit ce que
> User-Core *possède*, celui-ci dit ce qu'il *expose*. Patron : `CONTRAT_VERTICALE.md` de
> Payment-Core. Rédigé le 14/07/2026.
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

| # | Besoin réel | Ce que User-Core rend |
|---|---|---|
| 1 | « Qui est cet utilisateur ? » | Vérification du **jeton d'accès** par la **clé publique** (EdDSA, `kid` dans l'entête). Le programme **vérifie** un badge ; il ne peut pas en **fabriquer** un. |
| 2 | « Ce compte a-t-il MON programme activé ? » | Un **oui / non** sur **son** programme, avec la date d'activation. |
| 3 | « Comment je le désigne chez moi ? » | Un **identifiant de compte stable** (uuid technique), plus un **profil de base** minimal (nom d'affichage, langue). |

**C'est tout.** Un besoin qui n'entre dans aucune de ces trois lignes n'est pas une demande
d'intégration : c'est une demande de frontière, et elle se tranche avec l'Auditeur.

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
   pointent vers l'identifiant de compte.
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

- **Sa table de correspondance locale** (son entité métier ↔ l'identifiant de compte
  User-Core) : c'est le point de conception de l'extraction de Scolaria (CDC §8.5).
- **Ses rôles métier, ses données métier, ses écrans.** User-Core ne saura jamais qu'il existe
  une classe, une ordonnance ou un loyer — et c'est précisément ce qui lui permet de tous les
  servir.
