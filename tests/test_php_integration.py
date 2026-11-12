"""Optional real PostgreSQL/PHP checks, always on an isolated temporary database.

PHP_CLI=/path/to/php8.4 PG_BIN=/path/to/postgresql/17/bin python3 -m unittest discover -s tests -p test_php_integration.py -v
Run as an unprivileged user. No existing PostgreSQL instance is used.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / 'lib'))
from deploylib import safe_extract_app, render_template


@unittest.skipUnless(os.environ.get('PHP_CLI') and os.environ.get('PG_BIN') and os.geteuid() != 0,
                     'Requires PHP_CLI, PG_BIN and an unprivileged test user')
class RealPhpPostgresTests(unittest.TestCase):
    @classmethod
    def command(cls, argv, *, text=None, expected=0, env=None):
        process = subprocess.run([str(a) for a in argv], input=text, capture_output=True,
                                 text=True, env=env or cls.env, timeout=90)
        if process.returncode != expected:
            # Do not emit SQL bindings, passwords, environments or application logs.
            raise AssertionError(f'Command {Path(str(argv[0])).name} exited {process.returncode}; expected {expected}')
        return process.stdout + process.stderr

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='syscohada-autorun-pg-')
        cls.work = Path(cls.tmp.name)
        cls.php = os.environ['PHP_CLI']
        cls.pg = Path(os.environ['PG_BIN'])
        cls.env = {k:v for k,v in os.environ.items() if not k.startswith(('APP_', 'DB_', 'PGSSL', 'SESSION_', 'LOG_'))}
        cls.env['TMPDIR'] = str(cls.work)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); cls.port = str(sock.getsockname()[1])
        cls.data = cls.work / 'data'
        cls.command([cls.pg/'initdb','-D',cls.data,'--no-locale','--encoding=UTF8','--auth=trust'])
        cls.command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                     '-keyout',cls.work/'server.key','-out',cls.work/'server.crt',
                     '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'])
        (cls.work/'server.key').chmod(0o600)
        with (cls.data/'postgresql.conf').open('a') as cfg:
            cfg.write(f"\nlisten_addresses='127.0.0.1'\nport={cls.port}\nunix_socket_directories=''\nssl=on\nssl_key_file='{cls.work}/server.key'\nssl_cert_file='{cls.work}/server.crt'\npassword_encryption='scram-sha-256'\n")
        (cls.data/'pg_hba.conf').write_text('hostssl all syscohada_api 127.0.0.1/32 scram-sha-256\nhost all all 127.0.0.1/32 trust\n')
        cls.command([cls.pg/'pg_ctl','-D',cls.data,'-l',cls.work/'postgres.log','-w','start'])
        cls.dbpass = secrets.token_urlsafe(30)
        cls.sql(render_template((KIT/'templates/roles.sql.tpl').read_text(), {'DB_PASSWORD':cls.dbpass}))
        cls.command([cls.pg/'createdb','-h','127.0.0.1','-p',cls.port,'-O','syscohada_migrate','syscohada'])
        digest = json.loads((KIT/'payload/manifest.json').read_text())['sha256']
        cls.app = safe_extract_app(KIT/'payload/app.zip', cls.work/'release', digest)
        common = f'''APP_NAME="SYSCOHADA CM"
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:{base64.b64encode(secrets.token_bytes(32)).decode()}
APP_CIPHER=AES-256-GCM
APP_URL=https://dsf.example.com
APP_LOCALE=fr
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT={cls.port}
DB_DATABASE=syscohada
DB_SSLMODE=verify-full
SESSION_DRIVER=file
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
CACHE_STORE=file
QUEUE_CONNECTION=sync
LOG_CHANNEL=null
'''
        (cls.app/'.env.migration').write_text(common+'DB_USERNAME=syscohada_migrate\nDB_PASSWORD=\n')
        (cls.app/'.env.migration').chmod(0o600)
        (cls.app/'.env').write_text(common+f'DB_USERNAME=syscohada_api\nDB_PASSWORD={cls.dbpass}\n')
        (cls.app/'.env').chmod(0o600)
        cls.env['PGSSLROOTCERT'] = str(cls.work/'server.crt')
        for name in ['storage/framework/sessions','storage/framework/views','storage/framework/cache/data','storage/app/private','storage/logs','bootstrap/cache']:
            (cls.app/name).mkdir(parents=True, exist_ok=True)
        cls.command([cls.php,cls.app/'artisan','--env=migration','migrate','--force','--no-interaction'])
        # Test the actual installer grants using the non-superuser database owner.
        grants = render_template((KIT/'templates/runtime-grants.sql.tpl').read_text(), {})
        cls.sql(grants, database='syscohada', role='syscohada_migrate')
        cls.tenant, cls.actor = str(uuid.uuid4()), str(uuid.uuid4())
        cls.secret = cls.work/'bootstrap-secret'
        cls.password = 'T3st-'+secrets.token_urlsafe(24)
        cls.secret.write_text(cls.password+'\n'); cls.secret.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.command([cls.pg/'pg_ctl','-D',cls.data,'-m','immediate','-w','stop'])
        finally:
            cls.tmp.cleanup()

    @classmethod
    def sql(cls, query, database='postgres', role=None):
        options = ['-U',role] if role else []
        return cls.command([cls.pg/'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
                            '-h','127.0.0.1','-p',cls.port,'-d',database,*options], text=query)

    def bootstrap(self, *, email='admin@example.com', expected=0, env=None):
        return self.command([self.php,KIT/'bin/provision.php','--app',self.app,
                             '--secret-file',self.secret,'--tenant',self.tenant,
                             '--actor',self.actor,'--email',email,'--company','Test Autorun'],
                            expected=expected, env=env)

    def test_01_bootstrap_password_and_resume_preserve_identity(self):
        result = json.loads(self.bootstrap())
        self.assertTrue(result['ok']); self.assertFalse(result['resumed'])
        snapshot = self.sql('SELECT id,password FROM users;', database='syscohada')
        self.assertNotIn(self.password, snapshot)
        self.secret.write_text('OtherT3st-'+secrets.token_urlsafe(24)+'\n')
        second = json.loads(self.bootstrap())
        self.assertTrue(second['resumed'])
        self.assertEqual(snapshot, self.sql('SELECT id,password FROM users;',database='syscohada'))
        self.assertEqual('1', self.sql('SELECT count(*) FROM tenants;', database='syscohada').strip())

    def test_02_world_readable_secret_is_rejected(self):
        self.secret.chmod(0o644)
        try:
            output = self.bootstrap(expected=1)
            self.assertEqual('BOOTSTRAP_INPUT',json.loads(output)['code'])
            self.assertNotIn(self.password,output)
        finally: self.secret.chmod(0o600)

    def test_03_resume_cannot_change_admin_identity(self):
        self.assertEqual('BOOTSTRAP_PROVISION',json.loads(self.bootstrap(email='other@example.com',expected=1))['code'])

    def test_04_real_runtime_rls_and_http_dashboard(self):
        result = json.loads(self.command([self.php,KIT/'bin/check-runtime.php','--app',self.app,
                                         '--tenant',self.tenant,'--actor',self.actor]))
        self.assertTrue(result['ok'])
        self.assertIn('dashboard_http_200',result['checks'])
        self.assertIn('closed_context',result['checks'])

    def test_05_runtime_refuses_owner_credentials(self):
        env = dict(self.env, DB_USERNAME='syscohada_migrate', DB_PASSWORD='')
        output = self.command([self.php,KIT/'bin/check-runtime.php','--app',self.app,
                               '--tenant',self.tenant,'--actor',self.actor],expected=1,env=env)
        self.assertEqual('HEALTH_RUNTIME_ROLE',json.loads(output)['code'])

    def test_06_provision_ignores_runtime_config_cache(self):
        self.command([self.php,self.app/'artisan','config:cache'])
        self.assertTrue(json.loads(self.bootstrap())['resumed'])

    def test_07_runtime_requires_valid_server_ca(self):
        env = dict(self.env, PGSSLROOTCERT=str(self.work/'missing-ca.crt'))
        output = self.command([self.php,KIT/'bin/check-runtime.php','--app',self.app,
                               '--tenant',self.tenant,'--actor',self.actor],expected=1,env=env)
        self.assertFalse(json.loads(output)['ok'])
        self.assertNotIn(self.dbpass,output)


if __name__ == '__main__': unittest.main()
