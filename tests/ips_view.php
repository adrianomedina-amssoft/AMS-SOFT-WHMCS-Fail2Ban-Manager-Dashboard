<?php
namespace WHMCS\Database {
class Capsule {public static array $rows=[],$queries=[];public static bool $fail=false;public static function table($name){if($name!=='mod_amssoft_fail2ban_logs')throw new \RuntimeException('Unexpected table');return new Query;}}
class Query {
    private array $filters=[];
    public function where($key,$op,$value=null){if(func_num_args()===2){$value=$op;$op='=';}$this->filters[]=[$key,$op,$value];return $this;}
    public function whereIn($key,$values){$this->filters[]=[$key,'in',$values];return $this;}
    public function orderByDesc($key){return $this;}
    public function first($fields){Capsule::$queries[]=$this->filters;if(Capsule::$fail)throw new \RuntimeException('fixture SQL failure');foreach(Capsule::$rows as $r){$valid=true;foreach($this->filters as [$key,$op,$value])$valid=$valid&&match($op){'='=>$r[$key]===$value,'<='=>$r[$key]<=$value,'in'=>in_array($r[$key],$value,true)};if($valid)return (object)$r;}return null;}
}
}
namespace AMS\Fail2Ban {
class Database {public static array $geo=[];public static function withPresentationConfigCache($fn){return $fn();}public static function getGeoCache($ips){self::$geo=$ips;return [];}public static function getConfig($k,$d=null){return $d;}}
class Privileged {public static array $targets=[],$calls=[];public static bool $fail=false;public static function run($args){self::$calls[]=$args;if(array_slice($args,0,3)!==['--read-budget','10','tickets'])throw new \RuntimeException('Unexpected native call');return self::$fail?['success'=>false]:['success'=>true,'targets'=>self::$targets];}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{IpBanView as V,IpBanActions as A,Database as D,Privileged as P,Helper};use WHMCS\Database\Capsule as C;
$checks=0;function v41($ok,$why){global $checks;if(!$ok)throw new RuntimeException($why);$checks++;}
$_SESSION=['adminid'=>7];$ips=[];for($i=25;$i>=1;$i--)$ips[]='198.51.100.'.$i;
$native=['complete'=>true,'online'=>true,'statuses'=>['b'=>['banned_ip_list'=>['198.51.100.1','2001:db8::1']],'a'=>['banned_ip_list'=>$ips]],'unique_ips'=>26,'tickets'=>27,'at'=>time(),'error'=>null];
$out=V::select($native,[]);v41($out['records']===27&&$out['unique']===26,'Unique IP count vs ticket count');
v41($out['rows'][0]===['ip'=>'198.51.100.1','jail'=>'a']&&$out['rows'][1]['jail']==='b','Stable numeric IP then jail order');
v41(count($out['rows'])===10&&$out['pages']===3,'Page size');
$page=V::select($native,['page'=>'999']);v41($page['page']===3&&count($page['rows'])===7,'Page clamps after removals');
$filtered=V::select($native,['ip'=>'2001:0DB8:0:0:0:0:0:1']);v41($filtered['records']===1&&$filtered['filters']['ip']==='2001:db8::1','Expanded uppercase IPv6 search');
v41(V::select($native,['jail'=>'b'])['records']===2,'Filter per jail');
v41(V::select($native,['jail'=>'unloaded'])['records']===0,'Unknown jail not silently ignored');
foreach([['ip'=>[]],['jail'=>[]],['page'=>[]],['ip'=>'198.51.100.0/24'],['ip'=>'<script>'],['page'=>'-1']] as $query)v41(V::select($native,$query)['errors']!==[],'Invalid filter shape visible without TypeError');
foreach($native['statuses'] as $jail=>$status)foreach($status['banned_ip_list'] as $ip)$native['identities'][$jail.'|'.$ip]='2026-10-24 12:00:00 + 3600 = 2026-10-24 13:00:00';
C::$rows=[['ip'=>'198.51.100.1','jail'=>'b','action'=>'manual_ban','timestamp'=>'2026-10-20 10:00:00','reason'=>'wrong jail marker'],['ip'=>'198.51.100.1','jail'=>'a','action'=>'ban','timestamp'=>'2026-10-19 09:00:00','reason'=>'right jail marker']];
$view=V::read([],[],$native);v41($view['rows'][0]['history']['reason']==='right jail marker'&&$view['rows'][1]['history']['reason']==='wrong jail marker','Historical reasons scoped to exact IP/jail');
v41(count(C::$queries)===10&&count(D::$geo)<=10,'Enrichment only after pagination');
v41(P::$calls===[],'No extra native command after grouped snapshot');
v41(A::ticket($view['rows'][0]['preview'],'198.51.100.1','a')===$view['rows'][0]['ticket'],'Signed native ticket bound to row');
function render41($view){$modulelink='addonmodules.php?module=amssoft_fail2ban';$csrf_token='fixture';$asset_base='/fixture/';$e=fn($v)=>Helper::e($v);ob_start();include dirname(__DIR__).'/templates/ips_overview.tpl';return ob_get_clean();}
$html=render41($view);foreach(['26 IP(s) único(s)','27 ticket(s)','Uma linha por IP e jail','não identifica necessariamente o ban atual','não remove bans nas demais','Desbanir desta jail'] as $text)v41(str_contains($html,$text),'Rendered scope: '.$text);
$view['rows'][0]['history']['reason']='</script><img src=x onerror=alert(1)>';$view['rows'][0]['ticket']='"><script>bad()</script>';
v41(!str_contains(render41($view),'<img src=x')&&!str_contains(render41($view),'<script>bad()'),'History and native fields escaped');
$view=V::read([],['ip'=>'203.0.113'], $native);v41(str_contains(render41($view),'Nenhum ticket corresponde aos filtros'),'Filtered empty distinct from global empty');
$partial=$native;$partial['complete']=false;$partial['unique_ips']=null;$partial['tickets']=null;$partial['statuses']=[];
$view=V::read([],[],$partial);$html=render41($view);v41(str_contains($html,'Totais gerais não medidos')&&str_contains($html,'Não foi possível confirmar a ausência'),'Failed read never shows zero healthy');
$missing=$native;unset($missing['identities']);$view=V::read([],[],$missing);v41($view['rows'][0]['preview']===null&&$view['errors']!==[],'No temporal confirmation disables unban');
P::$fail=false;C::$fail=true;$view=V::read([],[],$native);v41(!$view['rows'][0]['history_known']&&$view['rows'][0]['preview']!==null,'Historical SQL failure does not hide native ticket');
C::$fail=false;$view=V::read([],['ban_ip'=>[],'open_modal'=>[]],$native);v41(!$view['open_modal']&&$view['ban_ip']==='','Malformed prefill safe');
$view=V::read([],['ban_ip'=>'2001:DB8::1','open_modal'=>'1'],$native);v41($view['open_modal']&&$view['ban_ip']==='2001:db8::1','IPv6 modal prefill');
echo "PASS: {$checks} IP list/filter/pagination/history/cache/token/template checks; simulated SQL/native\n";
}
