<?php
namespace WHMCS\Database {
class Capsule {static array $rows=[];static bool $fail=false;static function table($t){return new Query;}}
class Query {private string $prefix;private int $limit=0;function whereRaw($sql,$args){if($sql!=="`key` LIKE ? ESCAPE '='")throw new \RuntimeException('Wrong prefix contract');$this->prefix=$args[0]==='custom=_log.%'?'custom_log.':'logpath.';return $this;}function orderBy($c){return $this;}function limit($n){$this->limit=$n;return $this;}function get(){if(Capsule::$fail)throw new \RuntimeException('Unavailable');return array_map(fn($r)=>(object)$r,array_slice(array_values(array_filter(Capsule::$rows,fn($r)=>str_starts_with($r['key'],$this->prefix))),0,$this->limit));}}
}
namespace AMS\Fail2Ban {
class Router {public array $jails=[];public bool $fail=false;function makeJailConfig(){return $this;}function localHash(){return 'fixture';}function readJailLocal(){if($this->fail)throw new \RuntimeException('Unavailable');return $this->jails;}}
class LogPaths {static function inspect($p){$valid=is_string($p)&&str_starts_with($p,'/var/log/')&&!str_contains($p,'*');$real=$p==='/var/log/alias.log'?'/var/log/auth.log':$p;return ['valid'=>$valid,'readable'=>$valid&&!str_contains($p,'unreadable'),'canonical'=>$valid?$real:null,'message'=>$valid?'Fixture readable':'Fixture invalid','exists'=>$valid,'size'=>0,'status'=>$valid?'readable':'invalid'];}}
class LogTail {static function read($p,$c){return ['lines'=>['192.0.2.1 - - [x] "GET /.env?peer=192.0.2.99 HTTP/1.1" 404','mentioned 192.0.2.5 only'],'warnings'=>[],'bytes_read'=>100,'size'=>100];}}
class Database {static bool $fail=false;static array $ips=[];static function getGeoCache($ips){self::$ips=$ips;if(self::$fail)throw new \RuntimeException('Cache missing');return [];}}
}
namespace {
require dirname(__DIR__).'/lib/LogView.php';require dirname(__DIR__).'/lib/LogViewer.php';require dirname(__DIR__).'/lib/Safety.php';require dirname(__DIR__).'/lib/Helper.php';
use AMS\Fail2Ban\{LogView as V,Router,Database,Helper};use WHMCS\Database\Capsule as C;
$n=0;function cat47($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
$r=new Router;$r->jails=['DEFAULT'=>['logpath'=>'/var/log/default.log'],'test'=>['logpath'=>"/var/log/one.log\n/var/log/two.log"],'glob'=>['logpath'=>'/var/log/*.log']];
C::$rows=[['key'=>'custom_log.fixture','value'=>'/var/log/custom.log'],['key'=>'customXlog.fake','value'=>'/var/log/not-registered.log'],['key'=>'logpath.legacy','value'=>"/var/log/legacy1.log\n/var/log/legacy2.log"],['key'=>'custom_log.alias','value'=>'/var/log/alias.log']];
$c=V::catalog($r);$paths=array_column($c['logs'],'path');cat47(in_array('/var/log/custom.log',$paths,true),'Custom path');cat47(!in_array('/var/log/not-registered.log',$paths,true),'Literal underscore');cat47(in_array('/var/log/one.log',$paths,true)&&in_array('/var/log/two.log',$paths,true),'Multiline jail');cat47(in_array('/var/log/legacy2.log',$paths,true),'Multiline legacy');cat47(!in_array('/var/log/default.log',$paths,true),'Default not asserted source');cat47(!in_array('/var/log/alias.log',$paths,true),'Canonical deduplication');
foreach($c['logs'] as $log){if($log['path']==='/var/log/fail2ban.log')cat47(!$log['can_analyze'],'Operational log view only');if($log['path']==='/var/log/*.log')cat47(!$log['valid'],'Glob not expanded');}
try{V::allowed($c,'/etc/passwd');cat47(false,'External allowed');}catch(InvalidArgumentException $e){cat47(true,'Outside refused');}
C::$fail=true;$c=V::catalog($r);cat47(count($c['warnings'])===2&&count($c['logs'])>0,'SQL unknown explicit, known catalogue survives');C::$fail=false;$r->fail=true;cat47((bool)V::catalog($r)['warnings'],'Jail failure explicit');$r->fail=false;
$f=V::fetch($r,['path'=>'/var/log/custom.log','lines'=>'100']);cat47($f['success']&&$f['lines'][0]['peer']==='192.0.2.1'&&$f['lines'][1]['peer']===null,'Only source IP');cat47(!isset($f['lines'][0]['ips'])&&Database::$ips===['192.0.2.1'],'No arbitrary IP action and cache only origin');cat47($f['lines'][0]['class']==='suspicious','Heuristic retained');
Database::$fail=true;cat47((bool)V::fetch($r,['path'=>'/var/log/custom.log'])['warnings'],'Cache failure explicit');Database::$fail=false;
C::$rows=[];for($i=0;$i<501;$i++)foreach(['custom_log.','logpath.'] as $prefix)C::$rows[]=['key'=>$prefix.$i,'value'=>'/var/log/'.$prefix.$i.'.log'];
$r->jails=[];for($i=0;$i<3;$i++)$r->jails['large'.$i]=['logpath'=>implode("\n",array_map(fn($j)=>'/var/log/jail'.$i.'-'.$j.'.log',range(1,70)))];
$c=V::catalog($r);cat47(count($c['logs'])<=1100&&count($c['warnings'])>=3,'Per-source/record/global caps disclosed');cat47(!in_array('/var/log/custom_log.500.log',array_column($c['logs'],'path'),true),'501st registration not silently included');
$view=['logs'=>[['path'=>'/var/log/"bad.log','label'=>'<script>x</script>','valid'=>true,'readable'=>true,'can_analyze'=>true,'message'=>'ok']],'warnings'=>['<img src=x>'],'analysis_token'=>str_repeat('a',64),'analysis_lines'=>200];$modulelink='addonmodules.php?module=amssoft_fail2ban';$asset_base='/module/assets';$csrf_token='csrf';$e=fn($s)=>Helper::e($s);ob_start();include dirname(__DIR__).'/templates/logviewer_overview.tpl';$html=ob_get_clean();
cat47(!str_contains($html,'<script>x')&&!str_contains($html,'<img src=x>')&&str_contains($html,'&lt;script&gt;'),'Template escapes untrusted fields');cat47(str_contains($html,'for="viewer-path"')&&str_contains($html,'aria-live="polite"'),'Accessible labels/status');cat47(!str_contains($html,'onclick=')&&!str_contains($html,'function fetchLines'),'No inline executable data');cat47(str_contains($html,'não pausa Fail2Ban')&&str_contains($html,'não o filtro visual'),'Scope explicit');
echo "PASS: $n log viewer catalogue/source/cache/template checks; mocked SQL/filesystem\n";
}
