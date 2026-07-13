# User-Core

**Infrastructure de compte et d'identité** de l'écosystème (Scolaria, Mediyo, CheYo, Zando).
Scolaria en est le premier client, pas l'unique raison.

User-Core possède trois choses, et trois seulement :
1. **Le compte** — identifiants, secrets, sessions révocables, MFA, récupération.
2. **Le numéro de téléphone** — chiffré (jamais en clair), vérifié une fois par preuve de
   possession de ligne (SMS ou appel, jamais WhatsApp), avec la doctrine du numéro recyclé.
3. **Le catalogue des programmes** activés/désactivés — un droit d'accès, jamais un abonnement.

Il ne sait **jamais** ce qu'un compte fait dans un programme.

## Lire d'abord

- [CLAUDE.md](CLAUDE.md) — les règles inviolables de travail sur ce dépôt.
- [docs/CAHIER_DES_CHARGES.md](docs/CAHIER_DES_CHARGES.md) — le quoi/pourquoi complet :
  frontière, décision construire-vs-adopter, doctrine de vérification, invariants,
  décisions verrouillées.

## Parti pris

Les invariants vivent dans PostgreSQL, pas seulement dans le code. Zéro PII en clair.
Zéro suppression physique. Un seul service, sobre — on extrait quand une métrique le
réclame, jamais par anticipation.
