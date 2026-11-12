# Dedicated application cluster; no external PostgreSQL listener.
listen_addresses = 'localhost'
port = $PG_PORT
ssl = on
ssl_cert_file = '$PG_TLS_DIR/server.crt'
ssl_key_file = '$PG_TLS_DIR/server.key'
password_encryption = 'scram-sha-256'
log_statement = 'none'
log_min_error_statement = 'panic'
