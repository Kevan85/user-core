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
# --ignore-scripts : le « prepare » du dépôt appelle git, absent de cette image. Mesuré au
# 04/10/2026 : une seule dépendance de production a un script d'installation, argon2 — elle
# embarque son binaire précompilé (linux-x64, glibc) et le charge au démarrage, qui le
# prouve : le hachage de référence (C3) se calcule avant d'accepter le moindre trafic.
# CE CONSTAT EST UN MUR, PAS UNE PHRASE (C15, leçon ⑬) : la construction ÉCHOUE si les
# paquets installés que le verrou marque « hasInstallScript » diffèrent de la liste
# attendue, dans un sens ou dans l'autre. Sans lui, une dépendance qui télécharge ou
# compile son binaire à l'installation serait cassée dans l'image, et rien ne rougirait
# avant le déploiement. Un écart se TRANCHE — jamais en allongeant la liste par réflexe.
RUN npm ci --omit=dev --ignore-scripts \
 && node -e " \
      const fs = require('fs'); \
      const attendus = ['node_modules/argon2']; \
      const installes = Object.entries(require('./package-lock.json').packages) \
        .filter(([chemin, p]) => chemin !== '' && p.hasInstallScript === true && fs.existsSync(chemin)) \
        .map(([chemin]) => chemin).sort(); \
      const ecart = installes.filter((c) => !attendus.includes(c)) \
        .concat(attendus.filter((c) => !installes.includes(c))); \
      if (ecart.length > 0) { \
        console.error('REFUS — paquets de production à script d’installation : ' \
          + (installes.join(', ') || 'aucun') + ' ; attendus : ' + attendus.join(', ') \
          + ' ; écart : ' + ecart.join(', ')); \
        process.exit(1); \
      } \
      console.log('contrôle C15 : ' + installes.join(', ') + ' — conforme');"

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
