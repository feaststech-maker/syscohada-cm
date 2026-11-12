#!/usr/bin/env bash
set -euo pipefail
umask 077

KIT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
MODE=install VPS_IP='' SSH_USER=root SSH_PORT=22 DOMAIN='' EMAIL='' COMPANY='' KEY_FILE='' ACCEPT=no
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:?Mode manquant}"; shift 2 ;;
        --host) VPS_IP="${2:?IPv4 manquante}"; shift 2 ;;
        --user) SSH_USER="${2:?Utilisateur manquant}"; shift 2 ;;
        --port) SSH_PORT="${2:?Port manquant}"; shift 2 ;;
        --domain) DOMAIN="${2:?Domaine manquant}"; shift 2 ;;
        --email) EMAIL="${2:?Email manquant}"; shift 2 ;;
        --company) COMPANY="${2:?Entreprise manquante}"; shift 2 ;;
        --key) KEY_FILE="${2:?Clé manquante}"; shift 2 ;;
        --accept-acme-terms) ACCEPT=yes; shift ;;
        *) printf 'Argument inconnu : %s\n' "$1" >&2; exit 2 ;;
    esac
done
case "$MODE" in plan|install|resume|status) ;; *) printf '%s\n' 'Mode : plan, install, resume ou status.' >&2; exit 2 ;; esac
for tool in python3 ssh scp tar; do command -v "$tool" >/dev/null 2>&1 || { printf 'Outil requis : %s\n' "$tool" >&2; exit 2; }; done
for item in install.sh bin lib templates payload; do [[ -e "$KIT_DIR/$item" ]] || { printf 'Kit incomplet : %s\n' "$item" >&2; exit 2; }; done
[[ -n "$VPS_IP" ]] || read -r -p 'Adresse IPv4 publique du VPS Hostinger : ' VPS_IP
[[ "$SSH_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]{0,31}$ ]] || { printf '%s\n' 'Utilisateur SSH invalide.' >&2; exit 2; }
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535)) || { printf '%s\n' 'Port SSH invalide.' >&2; exit 2; }
if [[ -n "$KEY_FILE" && ! -f "$KEY_FILE" ]]; then printf '%s\n' 'Fichier de clé SSH introuvable.' >&2; exit 2; fi

NEEDS_CONFIG=no
if [[ "$MODE" == install || "$MODE" == plan ]]; then
    NEEDS_CONFIG=yes
    [[ -n "$DOMAIN" ]] || read -r -p 'Domaine, exemple dsf.votredomaine.com : ' DOMAIN
    DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
    [[ -n "$EMAIL" ]] || read -r -p 'Email administrateur et contact HTTPS : ' EMAIL
    [[ -n "$COMPANY" ]] || read -r -p 'Nom de l’entreprise : ' COMPANY
fi

TMP_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/syscohada-client.XXXXXXXX")"
trap 'rm -rf -- "$TMP_PARENT"' EXIT HUP INT TERM
STAGE="$TMP_PARENT/kit"
mkdir "$STAGE"
for item in install.sh bin lib templates payload README-FR.md config.example.json; do
    [[ ! -e "$KIT_DIR/$item" ]] || cp -R "$KIT_DIR/$item" "$STAGE/"
done

# Validate all remote-shell inputs, and write JSON without shell interpolation.
python3 - "$VPS_IP" "$NEEDS_CONFIG" "$DOMAIN" "$EMAIL" "$COMPANY" <<'PY'
import ipaddress,re,sys
ipaddress.IPv4Address(sys.argv[1])
if sys.argv[2]=='yes':
    domain,email,company=sys.argv[3:]
    if len(domain)>253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+',domain) or any(len(p)>63 for p in domain.split('.')):
        raise SystemExit('Domaine invalide, sans https:// ni chemin.')
    if len(email)>254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}",email):
        raise SystemExit('Adresse email invalide.')
    if not company.strip() or len(company)>200 or any(ord(c)<32 or ord(c)==127 for c in company):
        raise SystemExit('Nom d’entreprise invalide.')
PY

if [[ "$MODE" == install && "$ACCEPT" != yes ]]; then
    printf '\nLe certificat public Let’s Encrypt transmettra le domaine %s et le contact %s à l’autorité de certification.\n' "$DOMAIN" "$EMAIL"
    printf '%s\n' 'Conditions et accord : https://letsencrypt.org/repository/'
    read -r -p 'Acceptez-vous ces conditions pour ce déploiement ? Tapez OUI : ' answer
    [[ "$answer" == OUI ]] || { printf '%s\n' 'Émission non acceptée : aucun transfert ni déploiement lancé.' >&2; exit 2; }
    ACCEPT=yes
fi
if [[ "$NEEDS_CONFIG" == yes ]]; then
    python3 - "$STAGE/config.remote.json" "$DOMAIN" "$EMAIL" "$COMPANY" "$VPS_IP" "$ACCEPT" <<'PY'
import json,sys
with open(sys.argv[1],'w',encoding='utf-8') as out:
    json.dump(dict(domain=sys.argv[2],email=sys.argv[3],company=sys.argv[4],expected_ipv4=sys.argv[5],accept_acme_terms=sys.argv[6]=='yes'),out,ensure_ascii=False,indent=2)
PY
fi

REMOTE_NAME="syscohada-autorun-1.0.0-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
TARGET="$SSH_USER@$VPS_IP"
SSH_OPTIONS=(-p "$SSH_PORT" -o StrictHostKeyChecking=ask)
SCP_OPTIONS=(-P "$SSH_PORT" -o StrictHostKeyChecking=ask)
if [[ -n "$KEY_FILE" ]]; then SSH_OPTIONS+=(-i "$KEY_FILE"); SCP_OPTIONS+=(-i "$KEY_FILE"); fi
tar -czf "$TMP_PARENT/kit.tar.gz" -C "$STAGE" .
printf '\nCible : %s, port %s ; mode : %s.\n' "$TARGET" "$SSH_PORT" "$MODE"
printf '%s\n' 'OpenSSH réalise la vérification de clé et l’authentification. Le lanceur ne recueille pas le mot de passe SSH.'
ssh "${SSH_OPTIONS[@]}" "$TARGET" "umask 077; mkdir -- \"\$HOME/$REMOTE_NAME\" && chmod 700 -- \"\$HOME/$REMOTE_NAME\""
scp "${SCP_OPTIONS[@]}" "$TMP_PARENT/kit.tar.gz" "$TARGET:~/$REMOTE_NAME/kit.tar.gz"
REMOTE_COMMAND="cd \"\$HOME/$REMOTE_NAME\" && tar -xzf kit.tar.gz && "
[[ "$SSH_USER" == root ]] || REMOTE_COMMAND+='sudo -- '
REMOTE_COMMAND+="bash ./install.sh --$MODE"
[[ "$NEEDS_CONFIG" != yes ]] || REMOTE_COMMAND+=' --config ./config.remote.json'
ssh "${SSH_OPTIONS[@]}" -t "$TARGET" "$REMOTE_COMMAND"
printf '\nKit conservé dans ~/%s sur le VPS.\n' "$REMOTE_NAME"
printf '%s\n' 'En cas d’interruption, utilisez --resume dans ce dossier sur le serveur.'
