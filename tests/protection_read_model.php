<?php
if(PHP_SAPI!=='cli')exit(1);
$app=$argv[1]??dirname(__DIR__,4);
require $app.'/configuration.php';require $app.'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Router,Policy,NativeProbes,Maintenance};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();
$db=C::connection();$db->statement('SET TRANSACTION READ ONLY');$db->beginTransaction();$db->enableQueryLog();
$_SESSION=['adminid'=>1];$_GET=['action'=>'protection'];$_SERVER['REQUEST_METHOD']='GET';
$n=0;function verifyProtection($ok,$message){global $n;if(!$ok)throw new RuntimeException($message);$n++;}
try{
 $start=microtime(true);$router=new Router(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban','sudo_path'=>'/usr/bin/sudo','fail2ban_client'=>'/usr/bin/fail2ban-client']);$html=$router->dispatch('protection');$duration=microtime(true)-$start;
 $queries=$db->getQueryLog();$db->disableQueryLog();
 verifyProtection(count($queries)<800,'SQL query amplification');
 foreach($queries as $q)verifyProtection(!preg_match('/^\s*(insert|update|delete|alter|create|drop|truncate|replace)/i',$q['query']),'GET mutated SQL');
 $dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);
 foreach(Policy::fields() as $key=>$field)verifyProtection($xp->query('//*[@name="'.$key.'"]')->length===1,'Missing or duplicate control '.$key);
 verifyProtection($xp->query('//input[@name="policy_version"]')->item(0)->getAttribute('value')===\AMS\Fail2Ban\Database::getConfig('policy_version','0'),'GET carries current policy version');
 foreach(['protection-state','protection-settings','protection-diagnostics','protection-history','protection-maintenance'] as $id)verifyProtection($xp->query('//*[@id="'.$id.'"]')->length===1,'Missing section '.$id);
 foreach(NativeProbes::GROUPS as $group)verifyProtection($xp->query('//input[@data-native-group="'.$group.'"]')->length===1,'Missing closed native group '.$group);
 foreach($xp->query('//label[@for]') as $label)verifyProtection($xp->query('//*[@id="'.$label->getAttribute('for').'"]')->length===1,'Broken label');
 foreach($xp->query('//*[@role="tab"]') as $tab){verifyProtection($tab->hasAttribute('aria-selected'),'Tab selected state absent');verifyProtection($xp->query('//*[@id="'.$tab->getAttribute('aria-controls').'" and @role="tabpanel"]')->length===1,'Tab panel association absent');}
 verifyProtection($xp->query('//*[@id="maintenance-kind"]/option[1 and @value="monitor"]')->length===1,'Destructive default');
 verifyProtection($xp->query('//*[@id="maintenance-queue" and @disabled]')->length===1,'Confirmation initially enabled');
 verifyProtection($xp->query('//*[@id="protection-history"]//pre[not(ancestor::details)]')->length===0,'Expanded historical JSON');
 foreach(Maintenance::recent() as $job){$r=json_decode($job['result'],true);foreach(['first','last'] as $edge)verifyProtection(!isset($r['monitor'][$edge]['jail_coverage']),'Raw per-jail lists leaked to read model');}
 verifyProtection(strlen($html)<160000,'Page payload too large');
 $_GET['review_view']='history';$history=$router->dispatch('protection');$hd=new DOMDocument();$hd->loadHTML($history);$hx=new DOMXPath($hd);
 verifyProtection($hx->query('//button[contains(@class,"queue-requeue") and not(@disabled)]')->length===0,'Historical requeue invited');
 $_SERVER['REQUEST_METHOD']='POST';$_POST=['csrf_token'=>'invalid','ai_interval_minutes'=>'999'];$failed=$router->dispatch('protection');
 verifyProtection(str_contains($failed,'value="999"'),'Failed form discarded submitted values');
 $_POST=['csrf_token'=>['invalid']];$malformed=$router->dispatch('protection');
 verifyProtection(str_contains($malformed,'Sessão expirada'),'Array token rejected without crash');
 $oldVersion=(string)((int)\AMS\Fail2Ban\Database::getConfig('policy_version','0')-1);
 $_POST=['csrf_token'=>\AMS\Fail2Ban\Helper::csrfToken(),'policy_version'=>$oldVersion,'monitor_hours'=>'48'];
 $conflict=$router->dispatch('protection');$cd=new DOMDocument();$cd->loadHTML($conflict);$cx=new DOMXPath($cd);
 verifyProtection(str_contains($conflict,'Política alterada ou versão ausente'),'Stale form visibly refused');
 verifyProtection($cx->query('//input[@name="policy_version"]')->item(0)->getAttribute('value')===$oldVersion,'Rejected values cannot silently acquire a current version');
 echo 'PASS: '.$n.' protection read-model/DOM checks; READ ONLY SQL, no API/ban/reload; queries='.count($queries).' render_seconds='.round($duration,3).' html_bytes='.strlen($html)."\n";
}finally{$db->rollBack();}
