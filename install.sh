#!/usr/bin/env bash
# SYSCOHADA CM: thin entry point. Full checks and deployment live in bin/deploy.py.
set -euo pipefail
umask 077

KIT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
MODE=plan
MODE_COUNT=0
CONFIG_COUNT=0
ORIGINAL_ARGS=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install|--resume|--status|--plan)
            MODE="${1#--}"; MODE_COUNT=$((MODE_COUNT + 1)); shift ;;
        --config)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { printf '%s\n' 'Chemin de configuration manquant.' >&2; exit 2; }
            CONFIG_COUNT=$((CONFIG_COUNT + 1)); shift 2 ;;
        --config=*)
            [[ -n "${1#--config=}" ]] || { printf '%s\n' 'Chemin de configuration manquant.' >&2; exit 2; }
            CONFIG_COUNT=$((CONFIG_COUNT + 1)); shift ;;
        -h|--help)
            printf '%s\n' 'Usage : bash install.sh [--plan|--install|--resume|--status] [--config fichier.json]'
            exit 0 ;;
        *) printf 'Argument inconnu : %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [[ "$MODE_COUNT" -gt 1 || "$CONFIG_COUNT" -gt 1 ]]; then
    printf '%s\n' 'Utilisez un seul mode et un seul fichier de configuration.' >&2
    exit 2
fi

if [[ ! -f "$KIT_DIR/bin/deploy.py" ]]; then
    printf '%s\n' 'Kit incomplet : bin/deploy.py est absent.' >&2
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    if [[ "$MODE" != install && "$MODE" != resume ]]; then
        printf '%s\n' 'Python 3 est requis. Aucun logiciel ni service n’a été modifié.' >&2
        exit 2
    fi
    if [[ "$(id -u)" != 0 ]]; then
        printf '%s\n' 'Relancez ce mode avec sudo depuis votre VPS Hostinger Debian 13.' >&2
        exit 2
    fi
    if [[ ! -r /etc/os-release ]]; then
        printf '%s\n' 'Système non reconnu. Installation arrêtée avant modification.' >&2
        exit 2
    fi
    # Read fixed fields from the operating-system metadata; never source user config.
    OS_ID="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')"
    OS_VERSION="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')"
    if [[ "$OS_ID" != debian || "$OS_VERSION" != 13 ]]; then
        printf '%s\n' 'Le bootstrap automatique prend en charge Debian 13 uniquement.' >&2
        exit 2
    fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3
fi

exec python3 "$KIT_DIR/bin/deploy.py" "${ORIGINAL_ARGS[@]}"
