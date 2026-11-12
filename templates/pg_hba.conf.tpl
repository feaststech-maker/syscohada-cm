# Order matters: maintenance is Unix peer only, application is TLS/SCRAM only.
local   all           postgres                                  peer
local   syscohada     syscohada_migrate                          peer
local   all           all                                       reject
hostssl syscohada     syscohada_api       127.0.0.1/32           scram-sha-256
hostssl syscohada     syscohada_api       ::1/128                scram-sha-256
host    all           all                 0.0.0.0/0              reject
host    all           all                 ::0/0                  reject
