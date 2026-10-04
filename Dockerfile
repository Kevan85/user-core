# L'image de User-Core : l'API et le worker (lot déploiement, étape 3 — la pré-production).
#
# Trois étapes. Les dépendances de PRODUCTION s'installent seules ; la CONSTRUCTION
# compile avec les dépendances de développement ; l'EXÉCUTION ne reçoit que les
# premières et le résultat compilé — jamais les tests (dist/tests), jamais un fichier
# d'environnement (le contexte de construction est fermé par défaut : .dockerignore).
#
# L'image de base est ÉPINGLÉE PAR EMPREINTE : une étiquette se déplace, une empreinte
# non. Relevée le 04/10/2026 à 16:21 (index multi-architecture ; Node 22.23.3, Debian
# 12) ; la changer est un geste écrit dans docs/ops/DEPLOIEMENT.md §7.
#
# NODE_ENV n'est posé NULLE PART (F1, docs/ops/DEPLOIEMENT.md §2) : son absence arme les
# murs de production. Le poser ici les désarmerait tous d'un coup.

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS dependances-production
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts : le « prepare » du dépôt appelle git, absent de cette image, et aucune
# dépendance de production n'a besoin de son script d'installation — argon2 embarque son
# binaire précompilé (linux-x64, glibc) et le charge au démarrage, qui le prouve : le
# hachage de référence (C3) se calcule avant d'accepter le moindre trafic.
RUN npm ci --omit=dev --ignore-scripts

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS construction
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS execution
WORKDIR /app
COPY package.json ./
COPY --from=dependances-production /app/node_modules ./node_modules
COPY --from=construction /app/dist/src ./dist/src
COPY --from=construction /app/dist/scripts ./dist/scripts
# Le runner de migrations cherche ses fichiers à côté de lui : dist/scripts/../db/schema.
COPY db ./dist/db
# Le mur C8 lit .env.example dans le répertoire COURANT et refuse le démarrage s'il est
# introuvable : le fichier voyage avec le service, à la racine du répertoire de travail.
COPY .env.example ./
USER node
EXPOSE 3000
CMD ["node", "dist/src/main.js"]
