<?php
namespace AMS\Fail2Ban {
    class Database {public static array $row=[];public static function getSuggestion($id){return self::$row;}public static function withPresentationConfigCache($fn){return $fn();}}
    class Helper {static function adminId(){return 1;}static function checkCsrf($t){return $t==='fixture';}}
    class AIView {static function id($v){if(!is_string($v)||!ctype_digit($v))throw new \InvalidArgumentException('ID');return (int)$v;}static function projection(){return ['groups'=>['actionable'=>[]]];}}
    class Router {public function makeClient(){throw new \RuntimeException('Observation reached privileged preparation');}}
    class Policy {public static function number($key){return 70;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/controllers/AIController.php';
$_SERVER['REQUEST_METHOD']='POST';
$checks=0;function check($v,$m){global $checks;if(!$v)throw new RuntimeException($m);$checks++;}
$controller=new AMS\Fail2Ban\Controllers\AIController([],new AMS\Fail2Ban\Router);
foreach(['monitor','whitelist'] as $classification){
    AMS\Fail2Ban\Database::$row=['id'=>1,'status'=>'pending','classification'=>$classification];
    foreach(['approve','create_filter'] as $operation){$r=json_decode($controller->handleAjax($operation,['id'=>'1','csrf_token'=>'fixture']),true);check($r['success']===false,'Observation endpoint accepted mutation');}
}
$e=fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8');$modulelink='addonmodules.php?module=amssoft_fail2ban';
$pending=[['id'=>2,'ip'=>'203.0.113.2','classification'=>'ban','threat'=>'Probe','severity'=>'high','confidence'=>99,'jail'=>'suggested','filter_name'=>'fixture','failregex'=>'fixture','filter_created_at'=>null,'bantime'=>3600,'created_at'=>'2026-10-13','effectively_protected'=>true,'protection_label'=>'Cobertura confirmada até 13:05','evidence'=>[]]];
$pending_total=1;$pending_pages=$pending_page=1;$country_groups=[];$geo_data=[];
$observations=[['id'=>1,'ip'=>'203.0.113.1','classification'=>'monitor','threat'=>'Acesso legítimo','confidence'=>99,'created_at'=>'2026-10-13 12:00:00','evidence'=>['<script>alert(1)</script>']]];
$observations_total=$observations_pages=$observations_page=1;$history=[];$history_total=0;$history_pages=$history_page=1;
$filters=['status'=>'','severity'=>'','date_from'=>'','date_to'=>''];$ai_mode='threshold';$decision_view='actionable';$csrf_token='fixture';$asset_base='assets';
ob_start();require dirname(__DIR__).'/templates/ai_overview.tpl';$html=ob_get_clean();
$dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);
foreach(['amsfb-decisions','amsfb-observations','amsfb-history'] as $id)check($xp->query('//*[@id="'.$id.'"]')->length===1,'Tab missing');
check($xp->query('//*[@id="amsfb-observations"]//button')->length===0,'Observation has mutation buttons');
check($xp->query('//*[@id="amsfb-observations"]//input')->length===0,'Observation can be bulk-selected');
check($xp->query('//*[@id="amsfb-observations"]//script')->length===0,'Evidence is not escaped');
check($xp->query('//*[@id="amsfb-decisions"]//*[@id="amsfb-observations"]')->length===0,'Observation tab nested inside decisions');
check($xp->query('//*[@id="amsfb-decisions"]//input[contains(@class,"amsfb-row-cb") and @disabled]')->length===1,'Protected peer remains selectable');
check($xp->query('//*[@id="amsfb-decisions"]//button[contains(@class,"amsfb-approve-btn") and @disabled]')->length===1,'Protected peer invites duplicate ban');
check(str_contains($html,'Cobertura confirmada até 13:05'),'Protection confirmation deadline missing');
foreach($xp->query('//script[not(@src)]') as $script){$tmp=tempnam('/tmp','amsfb-ui-');try{file_put_contents($tmp,$script->textContent);exec('node --check '.escapeshellarg($tmp).' 2>&1',$out,$code);check($code===0,'UI JavaScript syntax');}finally{unlink($tmp);}}
foreach(['actionable','waiting','protected','checking','review','history'] as $decision_view){
    $pending[0]['effectively_protected']=$decision_view==='protected';$pending_pages=2;$pending_total=11;
    $decision_counts=['actionable'=>1,'protected'=>2,'checking'=>3,'review'=>4,'history'=>5];
    ob_start();require dirname(__DIR__).'/templates/ai_overview.tpl';$rendered=ob_get_clean();
    $d=new DOMDocument();$d->loadHTML($rendered);$x=new DOMXPath($d);$disabled=$decision_view!=='actionable';
    check(($x->query('//*[@id="amsfb-select-all" and @disabled]')->length===1)===$disabled,'Select-all view gate '.$decision_view);
    check(($x->query('//input[contains(@class,"amsfb-row-cb") and @disabled]')->length===1)===$disabled,'Row view gate '.$decision_view);
    check(($x->query('//button[contains(@class,"amsfb-approve-btn") and @disabled]')->length===1)===$disabled,'Approve view gate '.$decision_view);
    check(str_contains($rendered,'decision_view='.$decision_view.'&amp;pending_page=2'),'Pagination lost view '.$decision_view);
}
$dashboard=['decisions'=>['protected'=>['records'=>109,'ips'=>16,'recent'=>0,'history'=>109,'undated'=>0]],'protection_at'=>time(),'at'=>time(),'recent_minutes'=>30,
 'queue'=>['ready'=>30,'backoff'=>0,'awaiting_recheck'=>253,'historical_deferred'=>831],
 'observation_stats'=>['counts'=>['all'=>5887,'recent'=>21,'history'=>5866,'review'=>20],'ips'=>1200,'undated'=>0],
 'learning'=>['counts'=>['all'=>75,'pending'=>15,'criteria'=>28,'review'=>22,'completed'=>10],'total'=>22,'page'=>1,'pages'=>3,
 'data'=>[['id'=>9,'ip'=>'203.0.113.8','learning_group'=>'review','code'=>'<script>evil()</script>','retry_at'=>null,'updated_at'=>'2026-10-15','evidence'=>['<img src=x onerror=evil()>']]]]];
$decision_view='protected';$decision_counts['protected']=109;$observation_scope='review';$observations_page=1;$observations_pages=2;$learning_scope='review';
ob_start();require dirname(__DIR__).'/templates/ai_overview.tpl';$rendered=ob_get_clean();$d=new DOMDocument();$d->loadHTML($rendered);$x=new DOMXPath($d);
check(str_contains($rendered,'109 decisões / 16 IPs'),'Distinct units hidden');
check(str_contains($rendered,'Observações (5887)'),'Filtered page overwrote total observations');
check($x->query('//*[@id="amsfb-learning"]')->length===1,'Learning tab missing');
check($x->query('//*[@id="amsfb-decisions"]//*[@id="amsfb-learning"]')->length===0,'Learning tab nested in decisions');
check($x->query('//*[@id="amsfb-learning"]//button | //*[@id="amsfb-learning"]//input | //*[@id="amsfb-learning"]//script')->length===0,'Learning gained mutations or XSS');
check($x->query('//*[@id="amsfb-learning"]//img')->length===0,'Learning evidence XSS');
check(str_contains($rendered,'learning_scope=review&amp;learning_page=2#amsfb-learning'),'Learning pagination lost scope');
check(str_contains($rendered,'observation_scope=review&amp;observations_page=2#amsfb-observations'),'Observation pagination lost scope');
check(str_contains($rendered,'Tarefas de análise recentes prontas: 30'),'Real queue hidden');
check(str_contains($rendered,"'#'+pane.id===id"),'Tab switch can leave decisions active');
echo "PASS: {$checks} AI interface/endpoint checks; synthetic render, no host/SQL/API\n";
}
