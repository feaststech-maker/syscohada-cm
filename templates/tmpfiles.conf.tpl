# Financial temporary files stay in /run (tmpfs), private to each process account.
d /run/syscohada-php 0700 syscohada_web syscohada_web -
d /run/syscohada-cli 0700 syscohada_migrate syscohada_migrate -
d /run/syscohada-nginx 0700 www-data www-data -
