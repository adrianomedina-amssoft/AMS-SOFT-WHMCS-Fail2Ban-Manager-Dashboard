<?php
// Root-only read-only monitoring. Never invokes collection, API or ban methods.
if(PHP_SAPI!=='cli'||!function_exists('posix_geteuid')||posix_geteuid()!==0)exit(1);
$options=getopt('',['deadline:','interval:']);
$deadline=$options['deadline']??'';$interval=$options['interval']??'300';
if(!is_string($deadline)||!ctype_digit($deadline)||!is_string($interval)||!ctype_digit($interval)
    ||(int)$deadline<=time()||(int)$deadline>time()+604800||(int)$interval<30||(int)$interval>3600)exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule;
use AMS\Fail2Ban\{Database,BehaviorStore,QueueTelemetry,AnalysisWork};
$db=new Capsule;$db->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$db->setAsGlobal();$db->bootEloquent();
while(true){
    $final=time()>=(int)$deadline;
    try{
        $data=['timestamp'=>date('c'),'deadline'=>(int)$deadline,'final'=>$final,'scope'=>'queue_metrics_only',
            'schema'=>Database::getConfig('schema_version'),'queue'=>BehaviorStore::health(),
            'telemetry'=>QueueTelemetry::summary(),'subjects'=>AnalysisWork::health(),
            'learning_pending'=>count(json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[]),
            'error'=>Database::getConfig('ai_last_error','')];
    }catch(Throwable $e){$data=['timestamp'=>date('c'),'final'=>$final,'scope'=>'queue_metrics_only','measurement_error'=>get_class($e)];}
    echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE).PHP_EOL;flush();
    if($final)exit(0);
    sleep(max(1,min((int)$interval,(int)$deadline-time())));
}
