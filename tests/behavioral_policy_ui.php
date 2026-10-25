<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,Router,Policy};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');$db->beginTransaction();$n=0;
function behaviorUiCheck($value,$message){global $n;if(!$value)throw new RuntimeException($message);$n++;}
try{
 Database::setConfig('autoindex_review_report',json_encode(['at'=>date('c'),'examined_tickets'=>2,'released_tickets'=>2,'released_ips'=>1,'results'=>[['ip'=>'198.18.74.1','jail'=>'apache-autoindex-dir','result'=>'released','reason'=>'<img src=x onerror=evil()>']],'error'=>'<img src=x onerror=evil()>']));
 $_SESSION=['adminid'=>1];$_SERVER['REQUEST_METHOD']='GET';$router=new Router(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban','sudo_path'=>'/usr/bin/sudo','fail2ban_client'=>'/usr/bin/fail2ban-client']);$html=$router->dispatch('protection');
 $dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);
 foreach(['ai_application_probe_enabled','ai_application_probe_groups','ai_application_probe_min_confidence','ai_application_probe_min_events','ai_application_probe_min_apps','ai_application_probe_window_minutes'] as $key)behaviorUiCheck($xp->query('//*[@name="'.$key.'"]')->length===1,'Missing active field '.$key);
 behaviorUiCheck($xp->query('//*[@name="ai_application_probe_min_apps" and @min="3" and @max="13"]')->length===1,'Application limits absent');
 behaviorUiCheck(str_contains($html,'sitecore, solr, sugarcrm, qnap, spring, vmware'),'Extended active choices hidden');
 behaviorUiCheck(str_contains($html,'a simulação abaixo não executa bans'),'Simulation authority unclear');
 behaviorUiCheck(str_contains($html,'1 IPs liberados / 2 tickets removidos'),'Review units wrong');
 behaviorUiCheck($xp->query('//img[@onerror]')->length===0,'Review XSS');
 behaviorUiCheck(str_contains($html,'Revisão incompleta'),'Review failure hidden');
}finally{$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$n} behavioral policy/review DOM checks; SQL rollback, read-only native, no API/unban\n";
