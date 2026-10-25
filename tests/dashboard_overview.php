<?php
namespace WHMCS\Database {
class Capsule {
    public static array $tables=[],$fail=[]; public static int $writes=0;
    public static function table($name){if(in_array($name,self::$fail,true))throw new \RuntimeException('fixture SQL failure');return new Query($name);}
    public static function connection(){return new self;}
    public function transaction($fn){self::$writes++;return $fn();}
}
class Rows implements \IteratorAggregate {
    public function __construct(private array $rows){}
    public function getIterator(): \Traversable {return new \ArrayIterator($this->rows);}
    public function map($fn){return new self(array_map($fn,$this->rows));}
    public function all(){return $this->rows;}
}
class Query {
    private array $conditions=[],$orders=[];private ?int $limit=null;private ?string $group=null;
    public function __construct(private string $table){}
    public function where($key,$op,$val=null){if(func_num_args()===2){$val=$op;$op='=';}$this->conditions[]=fn($r)=>match($op){'='=>($r[$key]??null)===$val,'>='=>($r[$key]??null)>=$val,'<='=>($r[$key]??null)<=$val,default=>throw new \RuntimeException('Unknown operator')};return $this;}
    public function whereIn($key,$values){$this->conditions[]=fn($r)=>in_array($r[$key]??null,$values,true);return $this;}
    public function select(...$args){return $this;} public function selectRaw(...$args){return $this;}
    public function groupByRaw($field){$this->group='date';return $this;} public function groupBy($field){$this->group=$field;return $this;}
    public function orderByRaw($field){return $this->orderBy('date');}
    public function orderByDesc($field){return $this->orderBy($field,'desc');}
    public function orderBy($field,$direction='asc'){$this->orders[]=[$field,$direction];return $this;}
    public function limit($n){$this->limit=$n;return $this;}
    private function rows(){
        $rows=array_values(array_filter(Capsule::$tables[$this->table]??[],fn($r)=>!array_filter($this->conditions,fn($fn)=>!$fn($r))));
        if($this->group){$groups=[];foreach($rows as $r){$key=$this->group==='date'?substr($r['timestamp'],0,10):$r[$this->group];$groups[$key]=($groups[$key]??0)+1;}$rows=[];foreach($groups as $key=>$n)$rows[]=[$this->group=>$key,'count'=>$n];}
        if($this->orders)usort($rows,function($a,$b){foreach($this->orders as [$field,$dir]){if($cmp=($a[$field]??null)<=>($b[$field]??null))return $dir==='desc'?-$cmp:$cmp;}return 0;});
        return $this->limit===null?$rows:array_slice($rows,0,$this->limit);
    }
    public function get($fields=null){return new Rows(array_map(fn($r)=>(object)$r,$this->rows()));}
    public function first($fields=null){$rows=$this->rows();return $rows?(object)$rows[0]:null;}
    public function count(){return count($this->rows());}
    public function updateOrInsert(...$args){Capsule::$writes++;}
}
}
namespace AMS\Fail2Ban {
class Database {
    public static array $config=['schema_version'=>'37'];
    public static function getConfig($key,$default=null){return self::$config[$key]??$default;}
    public static function withPresentationConfigCache($fn){return $fn();}
    public static function getGeoCache($ips){return [];}
}
class Policy {
    public static function number($key){return $key==='ai_blocked_recheck_seconds'?300:30;}
    public static function values(){return ['ai_auto_enabled'=>'0','ai_mode'=>'threshold','ai_stale_minutes'=>'30','ai_cycle_seconds'=>'180'];}
}
class DecisionEligibility {public static function evaluate($r){return ['view'=>$r['fixture_view'],'reason'=>'fixture','latest'=>time(),'eligible'=>$r['fixture_view']==='actionable'];}}
class DecisionMemory {public static function policyFingerprint(){return 'fixture';}}
class Privileged {public static array $snapshot=[];public static int $calls=0;public static function run($args){self::$calls++;if($args!==['--read-budget','15','dashboard-protection-snapshot'])throw new \RuntimeException('Unexpected native action');return self::$snapshot;}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);date_default_timezone_set('America/Sao_Paulo');
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{DashboardOverview as D,DecisionProtection as DP,Privileged,Helper};use WHMCS\Database\Capsule as C;
$checks=0;function check40($value,$why){global $checks;if(!$value)throw new RuntimeException($why);$checks++;}
function rejected40($fn,$why){try{$fn();}catch(Throwable $e){check40(true,$why);return;}check40(false,$why);}
function status40($ips=[]){return "Status for jail\nCurrently failed: 0\nTotal failed: 4\nCurrently banned: ".count($ips)."\nTotal banned: 9\nBanned IP list: ".implode(' ',$ips)."\n";}
check40(D::jailNames("Number of jail: 0\nJail list:\n")===[],'Zero jails measured');
check40(D::jailNames("Number of jail: 2\nJail list: z, a\n")===['a','z'],'Sorted jail names');
foreach(["", "ERROR jail missing", "Number of jail: 2\nJail list: a", "Number of jail: 2\nJail list: a,a", "Number of jail: 1\nJail list: -evil"] as $bad)rejected40(fn()=>D::jailNames($bad),'Malformed list refused');
check40(D::jailStatus(status40())['currently_banned']===0,'Real zero retained');
check40(count(D::jailStatus(status40(['198.51.100.4','2001:db8::4']))['banned_ip_list'])===2,'IPv4 and IPv6 retained');
foreach(['',str_replace('Total failed: 4','Total failed: nope',status40()),status40(['bad']),status40(['198.51.100.1','198.51.100.1']),str_replace('Currently banned: 1','Currently banned: 2',status40(['198.51.100.1']))] as $bad)rejected40(fn()=>D::jailStatus($bad),'Malformed status refused');
$read=fn($args)=>count($args)===1?"Number of jail: 2\nJail list: a,b":status40(['198.51.100.4']);
$native=D::native([],$read);check40($native['complete']&&$native['unique_ips']===1&&$native['tickets']===2,'Unique peers across jails, tickets separate');
$partial=D::native([],fn($args)=>($args[1]??'')==='b'?'ERROR':$read($args));
check40(!$partial['complete']&&$partial['unique_ips']===null&&$partial['statuses']['b']===null&&$partial['statuses']['a']!==null,'Partial result not zero or complete');
$failed=D::native([],fn()=>throw new RuntimeException('timeout'));check40($failed['online']===null&&$failed['jails']===null,'Timeout not offline or zero');
$calls=0;$changed=D::native([],function($args)use(&$calls,$read){if(count($args)===1&&++$calls===2)return "Number of jail: 0\nJail list:";return $read($args);});
check40(!$changed['complete']&&$changed['jails']===null&&$changed['unique_ips']===null,'Concurrent jail list change invalidates total');
$empty=D::native([],fn()=>"Number of jail: 0\nJail list:");check40($empty['complete']&&$empty['unique_ips']===0,'Empty healthy daemon');
$now=strtotime('2026-10-24 15:00:00');$logs='mod_amssoft_fail2ban_logs';
C::$tables[$logs]=[
 ['id'=>1,'ip'=>'198.51.100.1','action'=>'ban','jail'=>'a','timestamp'=>'2026-10-22 01:00:00'],
 ['id'=>2,'ip'=>'198.51.100.2','action'=>'ban','jail'=>'b','timestamp'=>'2026-10-18 00:00:00'],
 ['id'=>3,'ip'=>'198.51.100.3','action'=>'ban','jail'=>'a','timestamp'=>'2026-10-17 23:59:59'],
 ['id'=>4,'ip'=>'198.51.100.9','action'=>'ban','jail'=>'a','timestamp'=>'2026-10-25 00:00:00'],
 ['id'=>5,'ip'=>'-','action'=>'jail_created','jail'=>'manual','admin_id'=>1,'timestamp'=>'2026-10-24 01:00:00'],
 ['id'=>6,'ip'=>'-','action'=>'jail_created','jail'=>'old','timestamp'=>'2026-10-23 01:00:00'],
];
$h=D::history($now);check40($h['count_24h']===0&&$h['last']['ip']==='198.51.100.1','Last ban independent of 24h and future excluded');
check40(count($h['days'])===7&&$h['days'][0]===['date'=>'2026-10-18','count'=>1]&&array_sum(array_column($h['days'],'count'))===2,'Seven calendar days exact boundary');
check40(count($h['top'])===3,'Top retained history excludes future');
check40($h['created_today']===1&&count($h['created_recent'])===1&&$h['created_recent'][0]['jail']==='manual','Only today listed without claiming AI origin');
C::$tables[$logs][]=['id'=>7,'ip'=>'198.51.100.7','action'=>'manual_ban','jail'=>'a','timestamp'=>'2026-10-23 15:00:00'];
check40(D::history($now)['count_24h']===1,'24h inclusive boundary');
$suggestions='mod_amssoft_fail2ban_ai_suggestions';$snap=['success'=>true,'stable'=>true,'observed_at'=>time(),'ttl'=>300,'errors'=>[],'requirements'=>['http'=>[80,443]],'entries'=>[['ip'=>'198.51.100.4','effective'=>true,'protocol'=>'tcp','ports'=>[80,443],'expires_at'=>time()+3600,'jail'=>'a','ticket'=>'fixture']]];
$row=['status'=>'pending','classification'=>'ban','source_log'=>'/var/log/apache2/access_whmcs.log','fixture_view'=>'actionable','created_at'=>'2026-10-24 12:00:00','threat'=>'fixture','confidence'=>99,'severity'=>'high'];
C::$tables[$suggestions]=[['id'=>1,'ip'=>'198.51.100.4']+$row,['id'=>2,'ip'=>'198.51.100.5']+$row,['id'=>3,'ip'=>'198.51.100.6','fixture_view'=>'history']+$row];
DP::reset();$projection=DP::refresh($snap,false);
check40($projection['groups']['protected']===[1]&&$projection['groups']['actionable']===[2]&&$projection['groups']['history']===[3],'Same shared protection/eligibility classification');
check40(C::$writes===0,'Read-only projection no writes');
$cache=new ReflectionProperty(DP::class,'projection');check40($cache->getValue()===null,'Read-only does not seed worker cache');
DP::refresh($snap);check40(C::$writes===4&&$cache->getValue()!==null,'Existing persistent refresh preserved');DP::reset();C::$writes=0;
Privileged::$snapshot=$snap;$decisions=D::decisions();check40($decisions['counts']['actionable']===1&&$decisions['counts']['protected']===1,'Dashboard excludes protected from actionable');
check40(C::$writes===0&&$cache->getValue()===null,'Dashboard decisions remain read-only');
foreach([['success'=>false],['stable'=>false],['observed_at'=>time()-301],['observed_at'=>time()+1],['errors'=>['bad']]] as $bad){Privileged::$snapshot=array_replace($snap,$bad);rejected40(fn()=>D::decisions(),'Unavailable snapshot not zero');}
Privileged::$snapshot=$snap;
C::$fail=[$logs];$overview=D::read(['sudo_path'=>'/nonexistent-fixture']);
check40($overview['history']===null&&$overview['ai']!==null&&$overview['decisions']!==null,'History failure isolated');
check40(!$overview['ai']['enabled']&&$overview['ai']['mode']==='threshold','Configured mode separate from automation switch');
C::$fail=[];C::$tables[$suggestions]=[];$before=Privileged::$calls;
check40(D::decisions()['counts']['actionable']===0&&Privileged::$calls===$before,'No decisions needs no native coverage query');
function page40($overview){$modulelink='addonmodules.php?module=amssoft_fail2ban';$e=fn($v)=>Helper::e($v);ob_start();include dirname(__DIR__).'/templates/dashboard_overview.tpl';return ob_get_clean();}
$overview['native']=$partial;$overview['history']=$h;$overview['decisions']=$decisions;
$overview['last_analysis']=['ip'=>'198.51.100.8','threat'=>'</script><img src=x onerror=alert(1)>','classification'=>'monitor','status'=>'pending','severity'=>'high','confidence'=>99,'created_at'=>'2026-10-24'];
$html=page40($overview);
foreach(['não medido','Automação: desligada','Observação — sem bloqueio','histórico retido do módulo','sete dias de calendário','não confirma disponibilidade atual','registros, não IPs únicos','Ver valores por dia','Status do registro'] as $text)check40(str_contains($html,$text),'Rendered semantics: '.$text);
check40(!str_contains($html,'<img src=x')&&!str_contains($html,'API OK'),'Escaped analysis and no stale API OK');
$overview['history']['top']=[['ip'=>'</script><script>evil()</script>','count'=>1]];$html=page40($overview);
check40(!str_contains($html,'<script>evil()'),'Chart JSON escaped');
$overview['history']=null;$overview['decisions']=null;$overview['ai']=null;$overview['last_analysis']=null;$overview['last_analysis_known']=false;
$html=page40($overview);check40(str_contains($html,'Histórico não medido.')&&str_contains($html,'Última análise não medida.'),'Unknown distinct from empty');
$overview['native']=$empty;$overview['last_analysis_known']=true;$html=page40($overview);
check40(str_contains($html,'Nenhuma jail carregada.')&&str_contains($html,'Nenhuma análise registrada.'),'Measured empty states');
check40(C::$writes===0,'All overview reads no SQL writes');
echo "PASS: {$checks} dashboard native/error/history/projection/render checks; mocked SQL/native, no API\n";
}
