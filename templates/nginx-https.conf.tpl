server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/syscohada-acme;
        try_files $$uri =404;
    }
    location / { return 301 https://$$host$$request_uri; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    root /opt/syscohada/current/public;
    index index.php;
    server_tokens off;
    access_log off;
    client_max_body_size 9m;
    client_body_temp_path /run/syscohada-nginx;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    if (-f /opt/syscohada/maintenance.flag) { return 503; }
    location / { try_files $$uri $$uri/ /index.php?$$query_string; }
    location ~ ^/index\.php(/|$$) {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $$realpath_root$$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $$realpath_root;
        fastcgi_param HTTPS on;
        fastcgi_hide_header X-Powered-By;
        fastcgi_buffering off;
        fastcgi_max_temp_file_size 0;
        fastcgi_pass unix:/run/php/syscohada.sock;
        fastcgi_read_timeout 90s;
    }
    location ~ \.php$$ { return 404; }
    location ~ /\. { deny all; }
}
