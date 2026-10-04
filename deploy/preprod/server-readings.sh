#!/bin/sh
# Relevés du serveur partagé avec Scolaria — LECTURE SEULE (docs/ops/DEPLOIEMENT.md §7.2).
# Joués depuis le poste, par l'alias DÉDIÉ « user-core-preprod », jamais par celui de
# Scolaria : UNE commande par saut SSH, le code de sortie lu CÔTÉ SERVEUR. Toujours depuis
# le blob, jamais la copie de travail (elle peut être en CRLF sous core.autocrlf=true) :
#
#   git show <SHA>:deploy/preprod/server-readings.sh | sh
#
# RIEN NE S'ÉCRIT SUR LE SERVEUR, pas même un temporaire. Ce qui s'affiche est FILTRÉ :
# - jamais la configuration complète de Scolaria ;
# - jamais l'adresse d'origine d'une connexion : le journal d'authentification ne sert qu'à
#   prouver QUELLE clé a été acceptée, et rien ne s'affiche si le retrait de l'adresse a
#   échoué ;
# - là où une sortie peut porter un secret (une ligne de cron, daemon.json), toute valeur
#   qui en a l'allure est masquée. C'est un masque d'APPOINT, pas une preuve : on ne relit
#   jamais un fichier entier.
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash : aucune conversion de chemin
hote=user-core-preprod
masque='s#(://[^:/@ ]+:)[^@ ]+@#\1<masqué>@#g; s#((pass(word|phrase)?|secret|token|pwd|key)[A-Za-z_]*"?[ ]*[=: ][ ]*"?)[^ ",]+#\1<masqué>#Ig'

# ssh -n : aucun relevé ne lit l'entrée standard (ce script peut arriver par un tube).
releve() {
  printf '\n### %s\n' "$1"
  ssh -n -o BatchMode=yes "$hote" "$2"'; echo "(code de sortie côté serveur : $?)"'
}

echo "relevés — début, heure du poste : $(date '+%Y-%m-%d %H:%M:%S %z')"
releve "heure du serveur" 'date -u +%Y-%m-%dT%H:%M:%SZ'
releve "preuve de séparation : les dernières clés ACCEPTÉES (heure et empreinte, jamais l'adresse)" \
  'f=/var/log/auth.log; lignes=$(if [ -r "$f" ]; then grep -h "Accepted publickey" "$f"; else journalctl -q --no-pager -o short-iso _COMM=sshd _COMM=sshd-session 2>/dev/null | grep "Accepted publickey"; fi | tail -n 4 | sed -E "s/ from [^ ]+ port [0-9]+//; s/ [^ ]+ sshd(-session)?\[[0-9]+\]: / /"); case "$lignes" in *" from "*) echo "MASQUAGE INCOMPLET — rien n est affiché";; *) printf "%s\n" "$lignes";; esac'
releve "système, architecture, processeurs" '. /etc/os-release && echo "$PRETTY_NAME"; uname -m; nproc'
releve "le /bin/sh du serveur (C19) et le shell de connexion de root" \
  'readlink -f /bin/sh; getent passwd root | cut -d: -f7; dpkg-query -W -f="\${Package} \${Version}\n" dash bash 2>/dev/null'
releve "mémoire" 'free -m'
releve "disque" 'df -h / /var/lib/docker'
releve "ports à l'écoute (adresse:port), et 3100 / 3199" \
  'ss -ltnH | awk "{print \$4}" | sort -u | tr "\n" " "; echo; echo "pris sur 3100 ou 3199 : $(ss -ltnH | awk "{print \$4}" | grep -cE ":(3100|3199)\$")"'
releve "Docker et compose" \
  'docker version --format "client {{.Client.Version}} · serveur {{.Server.Version}} · API {{.Server.APIVersion}}"; docker compose version; docker info --format "cgroup v{{.CgroupVersion}} · journaux {{.LoggingDriver}} · stockage {{.Driver}}"'
releve "daemon.json (lecture ; valeurs d'allure secrète masquées)" \
  "if [ -f /etc/docker/daemon.json ]; then sed -E '$masque' /etc/docker/daemon.json; else echo absent; fi"
releve "relais userland (docker-proxy)" \
  'pgrep -a docker-proxy | grep -oE "\-host-ip [^ ]+ -host-port [0-9]+ -container-ip [^ ]+ -container-port [0-9]+"; echo "processus docker-proxy : $(pgrep -c docker-proxy)"'
releve "réseaux Docker et leurs sous-réseaux" \
  'docker network ls -q | xargs docker network inspect -f "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}} {{end}}"'
releve "conteneurs (l'état de Scolaria AVANT)" 'docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"'
releve "nginx : version et sites activés" 'nginx -v 2>&1; ls -l /etc/nginx/sites-enabled/'
releve "nginx -T, FILTRÉ" \
  'nginx -T 2>/dev/null | grep -nE "^# configuration file|server_name|listen|ssl_certificate|ssl_protocols|ssl_ciphers|proxy_pass|X-Forwarded-For"'
releve "certificats, méthode de renouvellement et minuteries" \
  'certbot certificates 2>/dev/null | grep -E "Certificate Name|Domains|Expiry Date|Key Type"; grep -hE "^(authenticator|installer|webroot_path) " /etc/letsencrypt/renewal/*.conf 2>/dev/null; systemctl list-timers --all --no-pager 2>/dev/null | grep -iE "certbot|docker|nginx"'
releve "pare-feu" 'ufw status verbose'
releve "tâches planifiées qui agissent sur Docker, nginx ou certbot (valeurs d'allure secrète masquées)" \
  "{ crontab -l 2>/dev/null | sed 's|^|crontab de root : |'; for f in /etc/crontab /etc/cron.d/*; do [ -f \"\$f\" ] && sed \"s|^|\$f : |\" \"\$f\"; done; } | grep -E 'docker|nginx|certbot' | grep -vE ' : *#' | sed -E '$masque'"
releve "outils de l'étape 3" \
  'openssl version; git --version 2>&1; for o in sha256sum base64 cmp tr stat; do printf "%s : %s\n" "$o" "$(command -v "$o" || echo absent)"; done'
releve "répertoire de User-Core (attendu : absent)" 'ls -ld /opt/user-core 2>&1'
echo
echo "relevés — fin, heure du poste : $(date '+%Y-%m-%d %H:%M:%S %z')"
