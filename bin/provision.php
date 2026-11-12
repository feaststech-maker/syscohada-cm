<?php
declare(strict_types=1);

/** One-time CLI bootstrap. No HTTP route, password argument, or default shared password. */
ini_set('display_errors', '0');
ini_set('log_errors', '0');
ini_set('zend.exception_ignore_args', '1');
$phase = 'INPUT';
try {
    if (PHP_SAPI !== 'cli' || PHP_VERSION_ID < 80400 || !function_exists('posix_geteuid')) throw new RuntimeException('CLI_REQUIRED');
    $args = getopt('', ['app:', 'secret-file:', 'tenant:', 'actor:', 'email:', 'company:']);
    foreach (['app','secret-file','tenant','actor','email','company'] as $key) if (!isset($args[$key]) || !is_string($args[$key])) throw new RuntimeException('INPUT_REQUIRED');
    $root = realpath($args['app']);
    if ($root === false || !is_file($root.'/artisan') || !is_file($root.'/vendor/autoload.php')) throw new RuntimeException('APP_PATH');
    $env = realpath($root.'/.env.migration');
    if ($env === false || !is_file($env) || (fileperms($env) & 0007) !== 0 || !in_array(fileowner($env), [0,posix_geteuid()], true)) throw new RuntimeException('MAINTENANCE_ENV_PERMISSIONS');
    $secret = $args['secret-file'];
    if (is_link($secret) || !is_file($secret) || fileowner($secret) !== posix_geteuid() || (fileperms($secret) & 0077) !== 0 || filesize($secret) > 256) throw new RuntimeException('SECRET_PERMISSIONS');
    $password = rtrim((string)file_get_contents($secret), "\r\n");
    if (strlen($password) < 12 || strlen($password) > 72 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) throw new RuntimeException('PASSWORD_POLICY');
    $email = strtolower($args['email']);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254 || preg_match('/[\r\n]/', $email)) throw new RuntimeException('EMAIL');
    $companyName = trim($args['company']);
    if ($companyName === '' || mb_strlen($companyName) > 200 || preg_match('/[\x00-\x1f\x7f]/', $companyName)) throw new RuntimeException('COMPANY');

    // Ignore an existing runtime config cache when loading the maintenance identity.
    $cache = sys_get_temp_dir().'/syscohada-no-cache-'.bin2hex(random_bytes(16)).'.php';
    putenv('APP_CONFIG_CACHE='.$cache); $_ENV['APP_CONFIG_CACHE']=$cache; $_SERVER['APP_CONFIG_CACHE']=$cache;
    require $root.'/vendor/autoload.php';
    $app = require $root.'/bootstrap/app.php';
    $app->loadEnvironmentFrom('.env.migration');
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    if (!$app->environment('production') || Illuminate\Support\Facades\DB::getDriverName() !== 'pgsql') throw new RuntimeException('PRODUCTION_POSTGRES_REQUIRED');
    if (!Illuminate\Support\Str::isUuid($args['tenant']) || !Illuminate\Support\Str::isUuid($args['actor'])) throw new RuntimeException('IDENTIFIER');
    $phase = 'DATABASE';
    $role = Illuminate\Support\Facades\DB::selectOne("select rolname,rolsuper,rolbypassrls,exists(select 1 from pg_class c where c.relname='entries' and c.relnamespace='public'::regnamespace and c.relowner=r.oid) as owns_data from pg_roles r where rolname=current_user");
    $flag = static fn(mixed $value): bool => in_array($value, [true,1,'1','t','true'], true);
    if (!$role || $flag($role->rolsuper) || $flag($role->rolbypassrls) || !$flag($role->owns_data)) throw new RuntimeException('MAINTENANCE_ROLE');
    $tenant = $args['tenant']; $actor = $args['actor'];
    $context = $app->make(App\Support\TenantContext::class);
    $phase = 'PROVISION';
    $result = $context->run($tenant, $actor, function () use ($tenant,$actor,$email,$companyName,$password): array {
        $existing = App\Models\User::query()->find($actor);
        if ($existing) {
            if ($existing->tenant_id !== $tenant || $existing->email !== $email || $existing->role !== 'TENANT_ADMIN' || !$existing->enabled) throw new RuntimeException('EXISTING_IDENTITY_MISMATCH');
            $company = App\Models\Company::query()->first();
            if (!$company || $company->name !== $companyName || !Illuminate\Support\Facades\DB::table('tenants')->where('id',$tenant)->exists()) throw new RuntimeException('EXISTING_TENANT_MISMATCH');
            // Resume never resets the password or re-seeds accounting data.
            return ['ok'=>true,'resumed'=>true,'tenant_id'=>$tenant,'actor_id'=>$actor,'company_id'=>(string)$company->id];
        }
        if (Illuminate\Support\Facades\DB::table('users')->exists() || Illuminate\Support\Facades\DB::table('tenants')->where('id',$tenant)->exists()) throw new RuntimeException('NONEMPTY_APPLICATION');
        Illuminate\Support\Facades\DB::table('tenants')->insert(['id'=>$tenant,'name'=>$companyName,'created_at'=>now(),'updated_at'=>now()]);
        $user = new App\Models\User(['name'=>'Administrateur','email'=>$email,'password'=>$password]);
        $user->id=$actor; $user->tenant_id=$tenant; $user->role='TENANT_ADMIN'; $user->enabled=true; $user->save();
        $company = app(App\Support\CompanySetup::class)->create(['name'=>$companyName,'niu'=>null,'accounting_system'=>'SMT','fiscal_regime'=>null,'virtual_accounting_enabled'=>true]);
        App\Models\FiscalYear::create(['company_id'=>$company->id,'starts_on'=>now()->startOfYear()->format('Y-m-d'),'ends_on'=>now()->endOfYear()->format('Y-m-d'),'status'=>'OPEN']);
        if (!Illuminate\Support\Facades\Hash::check($password, $user->password)) throw new RuntimeException('PASSWORD_HASH');
        return ['ok'=>true,'resumed'=>false,'tenant_id'=>$tenant,'actor_id'=>$actor,'company_id'=>(string)$company->id];
    });
    unset($password);
    fwrite(STDOUT,json_encode($result,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE).PHP_EOL);
    exit(0);
} catch (Throwable $error) {
    // No SQL, bindings, file contents, password, environment or stack trace is printed.
    fwrite(STDERR,json_encode(['ok'=>false,'code'=>'BOOTSTRAP_'.$phase,'message'=>'Initialisation refusée. Vérifiez les paramètres et les permissions de cette étape.']).PHP_EOL);
    exit(1);
}
