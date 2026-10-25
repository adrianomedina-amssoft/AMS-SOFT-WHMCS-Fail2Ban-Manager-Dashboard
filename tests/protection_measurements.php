<?php
namespace AMS\Fail2Ban {
class Database {public static function getConfig($key,$default=null){return $default;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Policy,Helper};
$checks=0;
function pmCheck($value,$why){global $checks;if(!$value)throw new RuntimeException($why);$checks++;}
function measurementPage(array $jail,array $cycle,array $overrides=[]): string {
    $values=array_replace(Policy::values(),$overrides);$fields=Policy::fields();$submittedValues=$values;$version='7';$lastRun=time();
    $health=['collector'=>time(),'cycle'=>time(),'backlog'=>0,'queue'=>[],'jail'=>$jail,'telemetry'=>['last'=>$cycle],'usage'=>'{}','calls'=>null,'retry_calls'=>null];
    $jobs=$reviewTasks=$heldTasks=$learningQueue=$learningUsage=$autoindexReview=[];
    $error=null;$modulelink='addonmodules.php?module=amssoft_fail2ban';$csrf_token='fixture';$asset_base='/fixture/';$e=fn($v)=>Helper::e($v);
    ob_start();include dirname(__DIR__).'/templates/protection.tpl';return ob_get_clean();
}
function diagnosticValue(string $html,string $label): string {
    $dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML('<?xml encoding="UTF-8">'.$html);$xp=new DOMXPath($dom);
    return trim($xp->query('//tr[th[text()="'.$label.'"]]/td')->item(0)->textContent);
}
foreach([[],['success'=>false],['success'=>false,'ticket_count'=>9],['success'=>true,'ticket_count'=>null],['success'=>true,'ticket_count'=>'bad']] as $unknown){
    $html=measurementPage($unknown,[]);
    pmCheck(str_contains($html,'Fila não medida'),'Missing queue is visibly unknown');
    pmCheck(str_contains($html,'<td>Prontas agora</td><td>não medido</td>'),'Missing ready category is not zero');
    pmCheck(str_contains($html,'não medido tarefas / não medido IPs'),'Missing held counters are not zero');
    pmCheck(str_contains($html,'Tickets na jail da IA: não medido'),'Failed/missing/null/malformed jail measurement is unknown');
    pmCheck(str_starts_with(diagnosticValue($html,'Sujeitos prontos no fim daquele ciclo'),'não medido'),'Missing work health is unknown');
    pmCheck(diagnosticValue($html,'Validações reaproveitadas no ciclo')==='não medido','Missing cache metric is unknown');
    pmCheck(str_starts_with(diagnosticValue($html,'Chamadas'),'não medido'),'Missing calls are unknown');
}
foreach([0,7] as $known){
    $html=measurementPage(['success'=>true,'ticket_count'=>$known],['work_health'=>['unique_subjects_ready'=>$known],'validation_cache'=>['cache_hits'=>$known]]);
    pmCheck(str_contains($html,'Tickets na jail da IA: '.$known.'.'),'Measured jail count stays measured');
    pmCheck(str_starts_with(diagnosticValue($html,'Sujeitos prontos no fim daquele ciclo'),(string)$known),'Measured work health including zero preserved');
    pmCheck(diagnosticValue($html,'Validações reaproveitadas no ciclo')===(string)$known,'Measured cache count including zero preserved');
}
$html=measurementPage([],[]);
pmCheck(str_contains($html,'id="ai_query_probe_decision_minutes"'),'Decision age control missing');
pmCheck(str_contains($html,'idade máxima efetiva de 30 min'),'Decision age summary missing');
pmCheck(!str_contains($html,'id="query-timing-warning"'),'Unexpected timing warning');
$html=measurementPage([],[],['ai_query_probe_decision_minutes'=>'5']);
pmCheck(str_contains($html,'id="query-timing-warning"'),'Short decision age warning missing');
pmCheck(str_contains($html,'eventos individuais em até 5 min'),'Burst interval not visible');
$html=measurementPage([],[],['ai_analysis_recent_minutes'=>'10']);
pmCheck(str_contains($html,'idade máxima efetiva de 10 min')&&str_contains($html,'id="query-timing-warning"'),'Global cap diagnostic incorrect');
$html=measurementPage([],[],['ai_query_probe_enabled'=>'0','ai_query_probe_decision_minutes'=>'5']);
pmCheck(!str_contains($html,'id="query-timing-warning"'),'Disabled detector warned');
echo "PASS: {$checks} unknown/zero/positive rendered measurement checks; no SQL/API/native\n";
}
