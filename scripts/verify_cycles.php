<?php
// Bounded read-only observer. Never loads hooks or triggers API, collection or bans.
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,Policy,Privileged,AIAnalyzer,CycleObserver};

require dirname(__DIR__).'/lib/CycleObserver.php';
$emit=static function(array $data): void {
    echo json_encode(['timestamp'=>date('c')]+$data,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    flush();
};
try {
    $options=CycleObserver::options(array_slice($argv??[],1));
} catch (InvalidArgumentException $e) {
    $emit(['status'=>'usage_error','error'=>$e->getMessage()]);exit(1);
}
if(PHP_SAPI!=='cli'||!function_exists('posix_geteuid')||posix_geteuid()!==0)exit(1);
try {
    require dirname(__DIR__,4).'/configuration.php';
    require dirname(__DIR__,4).'/vendor/autoload.php';
    require dirname(__DIR__).'/lib/Router.php';
    $db=new Capsule();
    $db->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
        'password'=>$db_password,'charset'=>'utf8mb4']);
    $db->setAsGlobal();$db->bootEloquent();
    $limits=['calls'=>Policy::number('ai_cycle_max_calls'),'seconds'=>Policy::number('ai_cycle_seconds'),
        'retry_percent'=>Policy::number('ai_retry_call_percent')];
    exit(CycleObserver::watch($options,$limits,AIAnalyzer::RECOVERY_GENERATION,
        static fn()=>CycleObserver::history(Database::getConfig('ai_cycle_metrics','[]')),
        static fn()=>Privileged::run(['--read-budget','30','audit-snapshot']),$emit,
        static fn()=>hrtime(true)/1e9,static fn()=>time(),
        static function(float $seconds): void {usleep((int)ceil($seconds*1000000));}));
} catch (Throwable $e) {
    // Do not expose credentials, SQL, raw command output or API responses.
    $emit(['status'=>'incomplete','kind'=>'operational','reason'=>'observer_unavailable',
        'error_type'=>get_class($e),'historical_coverage_attested'=>false]);exit(3);
}
