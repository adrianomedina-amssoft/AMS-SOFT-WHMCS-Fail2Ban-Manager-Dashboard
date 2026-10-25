<?php
namespace AMS\Fail2Ban {
class Database {public static function getConfig($key,$default=''){return $key==='schema_version'?'31':$default;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{RequestEvidence,AutoBanEngine};
$n=0;function axCheck($value,$label){global $n;if(!$value)throw new RuntimeException($label);$n++;}
function axLine($directory,$peer='198.51.100.77'){
 return '['.date('D M d H:i:s Y').'] [autoindex:error] [pid 123:tid 123] [client '.$peer.':54321] AH01276: Cannot serve directory '.$directory.': No matching DirectoryIndex (index.html,index.php) found, and server-generated directory index forbidden by Options directive';
}
foreach(['198.51.100.77','2001:db8::77'] as $ip){
 foreach(['/var/www/html/','/var/www/html/whmcs/','/var/www/license-example/','/var/www/html/public/','/var/www/html/.env.example/'] as $path){
  $line=axLine($path,$ip);axCheck(RequestEvidence::target($line)===$path,'Structured directory not extracted');
  axCheck(RequestEvidence::nonOffensiveLine($line),'Operational directory became attack');
  $s=['ip'=>$ip,'evidence'=>array_fill(0,4,$line),'failregex'=>'^.*<HOST>.*AH01276.*','confidence'=>99,'classification'=>'ban'];
  axCheck(RequestEvidence::nonOffensiveOnly($s),'Repeated errors became offensive');
  axCheck(AutoBanEngine::evidenceFilterDiagnostic($s)['code']==='filter_signal','Native validation reached for operational-only proof');
  AutoBanEngine::normalizeEvidenceFilter($s);axCheck($s['_native_validated']===false,'Normalization accepted operational proof');
  axCheck(RequestEvidence::nonOffensiveLine($line.', referer: https://example.invalid/.env'),'Referrer forged offense');
 }
 foreach(['/var/www/html/.env/','/var/www/html/.git/','/var/www/html/.aws/credentials/','/var/www/html/../etc/passwd/','/var/www/html/wp-admin/','/var/www/html/.env.example/.git/','/var/www/html/.git/.env.example/'] as $path)
  axCheck(!RequestEvidence::nonOffensiveLine(axLine($path,$ip)),'Explicit sensitive directory discarded');
 $root=axLine('/var/www/html/',$ip);$attack=axLine('/var/www/html/.git/',$ip);
 axCheck(!RequestEvidence::nonOffensiveOnly(['ip'=>$ip,'evidence'=>[$root,$attack]]),'Mixed offensive proof discarded');
 axCheck(RequestEvidence::nonOffensiveLine(substr($root,0,strpos($root,': No matching'))),'Incomplete error became offense');
}
$t=time()-10;$solr=[];
foreach(['/solr/admin/info/system','/solr/admin/cores?action=STATUS&wt=json'] as $target){
 $line='198.51.100.77 - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$target.' HTTP/1.1" 404 10 "-" "fixture"';
 axCheck(\AMS\Fail2Ban\ProbeApplications::application($line)==='solr','Closed Solr endpoint unavailable');
 axCheck(\AMS\Fail2Ban\ProbeSimulation::application($line,['solr'])['application']==='solr','Simulation disagrees');
 $solr[]=['line'=>$line];
}
$stats=\AMS\Fail2Ban\ProbeApplications::stats($solr,'198.51.100.77',$t-1);
axCheck($stats['events']===2&&$stats['applications']===1,'Two Solr endpoints became different applications');
foreach(['/solr/admin/cores-extra','/prefix/solr/admin/cores','/solr/admin/cores/child','/index.php?url=/solr/admin/cores'] as $target){
 $line='198.51.100.77 - - ['.date('d/M/Y:H:i:s O',$t).'] "GET '.$target.' HTTP/1.1" 404 10 "-" "fixture"';
 axCheck(\AMS\Fail2Ban\ProbeApplications::application($line)===null,'Solr recognition broadened');
}
echo "PASS: {$n} autoindex/Solr semantic checks; pure, no SQL/API/native mutations\n";
}
