<?php
if(PHP_SAPI!=='cli')exit(1);
$e=static fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8');$n=0;
function simUiCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
$report=['at'=>time(),'valid_until'=>time()+300,'window_minutes'=>30,'min_events'=>3,'min_apps'=>3,
    'subjects'=>1,'criteria_met'=>1,'excluded_protected'=>2,'excluded_unknown'=>0,'excluded_whitelist'=>1,
    'partial'=>true,'results'=>[['ip'=>'198.51.100.7','source_log'=>'/var/log/apache2/access_whmcs.log',
    'events'=>3,'applications'=>3,'groups'=>['servlet','solr','sugarcrm'],'paths'=>['<script>evil()</script>'],
    'latest'=>time(),'criteria_met'=>true]]];
foreach(['measured','expired','disabled','policy_changed','coverage_unavailable','awaiting_measurement'] as $status){
    $simulation=['status'=>$status,'report'=>$report,'error'=>'<img src=x onerror=evil()>'];
    ob_start();require dirname(__DIR__).'/templates/probe_simulation.tpl';$html=ob_get_clean();
    $dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);
    simUiCheck($xp->query('//*[@id="amsfb-probe-simulation"]')->length===1,'Panel missing');
    simUiCheck($xp->query('//button | //input | //script | //img | //form')->length===0,'Simulation has mutation controls or XSS');
    simUiCheck(str_contains($html,'não chama a IA'),'No-API boundary not explained');
    simUiCheck(str_contains($html,'Amostra parcial'),'Partial report hidden');
    simUiCheck(str_contains($html,'Medição anterior, não vigente')===($status!=='measured'),'Stale report labelled current');
}
echo "PASS: {$n} simulation UI checks; no SQL/API/native\n";
