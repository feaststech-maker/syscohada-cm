#!/bin/sh
set -eu
if [ "$${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/$DOMAIN" ]; then
    /usr/sbin/nginx -t
    /usr/bin/systemctl reload nginx
fi
