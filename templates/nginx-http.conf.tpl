# Initial issuance only: financial application stays unavailable until verified HTTPS.
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/syscohada-acme;
        try_files $$uri =404;
    }
    location / { return 503; }
}
