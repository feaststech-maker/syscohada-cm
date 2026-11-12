<?php
declare(strict_types=1);
ini_set('display_errors','0');ini_set('log_errors','0');ini_set('zend.exception_ignore_args','1');
$phase='INPUT';
try {
    if (PHP_SAPI!=='cli' || PHP_VERSION_ID<80400) throw new RuntimeException('CLI_REQUIRED');
    $args=getopt('',['app:','tenant:','actor:']);
    foreach(['app','tenant','actor'] as $key) if(!isset($args[$key]) || !is_string($args[$key])) throw new RuntimeException('INPUT');
    $root=realpath($args['app']);
    if(!$root || !is_file($root.'/artisan') || !is_file($root.'/vendor/autoload.php')) throw new RuntimeException('APP');
    require $root.'/vendor/autoload.php';
    $app=require $root.'/bootstrap/app.php';
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    if(!$app->environment('production') || Illuminate\Support\Facades\DB::getDriverName()!=='pgsql' || config('app.debug')) throw new RuntimeException('PRODUCTION_CONFIG');
    $phase='RUNTIME_ROLE';
    $role=Illuminate\Support\Facades\DB::selectOne("select rolname,rolsuper,rolbypassrls,exists(select 1 from pg_class c where c.relname='entries' and c.relnamespace='public'::regnamespace and c.relowner=r.oid) as owns_data from pg_roles r where rolname=current_user");
    $flag=static fn(mixed $v):bool=>in_array($v,[true,1,'1','t','true'],true);
    if(!$role || $flag($role->rolsuper) || $flag($role->rolbypassrls) || $flag($role->owns_data)) throw new RuntimeException('PRIVILEGED_RUNTIME');
    foreach(['companies','entries','entry_lines','audit_events','admin_settings'] as $table) {
        $meta=Illuminate\Support\Facades\DB::selectOne("select relrowsecurity,relforcerowsecurity from pg_class where relname=? and relnamespace='public'::regnamespace",[$table]);
        if(!$meta || !$flag($meta->relrowsecurity) || !$flag($meta->relforcerowsecurity)) throw new RuntimeException('RLS_MISSING');
    }
    if(Illuminate\Support\Facades\DB::table('companies')->count()!==0 || Illuminate\Support\Facades\DB::table('entries')->count()!==0) throw new RuntimeException('CONTEXT_NOT_CLOSED');
    $phase='HTTP';
    $user=App\Models\User::findOrFail($args['actor']);
    if($user->tenant_id!==$args['tenant'] || !$user->enabled || $user->role!=='TENANT_ADMIN') throw new RuntimeException('BOOTSTRAP_IDENTITY');
    Illuminate\Support\Facades\Auth::login($user);
    $request=Illuminate\Http\Request::create(rtrim((string)config('app.url'),'/').'/dashboard','GET');
    $kernel=$app->make(Illuminate\Contracts\Http\Kernel::class);$response=$kernel->handle($request);
    if($response->getStatusCode()!==200 || !str_contains($response->getContent(),'SYSCOHADA')) throw new RuntimeException('DASHBOARD');
    $kernel->terminate($request,$response);
    if(Illuminate\Support\Facades\DB::table('companies')->count()!==0) throw new RuntimeException('TENANT_CONTEXT_LEAK');
    $phase='STORAGE';
    if(!is_writable($root.'/storage/framework/sessions') || !is_writable($root.'/storage/app/private')) throw new RuntimeException('STORAGE_PERMISSIONS');
    fwrite(STDOUT,json_encode(['ok'=>true,'checks'=>['limited_runtime_role','force_rls','closed_context','dashboard_http_200','private_storage']],JSON_THROW_ON_ERROR).PHP_EOL);exit(0);
}catch(Throwable $error){
    fwrite(STDERR,json_encode(['ok'=>false,'code'=>'HEALTH_'.$phase,'message'=>'Contrôle de démarrage non satisfait. Le déploiement ne doit pas être déclaré prêt.']).PHP_EOL);exit(1);
}
