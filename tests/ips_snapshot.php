<?php
namespace WHMCS\Database {
    class Capsule {public static function table($t){return new Query;}}
    class Query {public function __call($m,$a){return $this;}public function first($fields){return null;}}
}
namespace AMS\Fail2Ban {
    class Database {public static function withPresentationConfigCache($f){return $f();}public static function getGeoCache($ips){return [];}}
    class Privileged {
        public static array $result=[],$calls=[];public static bool $fail=false;
        public static function run($args){self::$calls[]=$args;if(self::$fail)throw new \RuntimeException('Timeout');if($args!==['--read-budget','5','ips-snapshot'])throw new \RuntimeException('Unexpected command');return self::$result;}
    }
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{IpBanSnapshot as S,IpBanView as V,IpBanActions as A,Privileged as P,DashboardOverview as D};
$checks=0;function s43($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
function fixture43($at=1000){
 $status=['currently_failed'=>0,'total_failed'=>2,'currently_banned'=>2,'total_banned'=>3,'banned_ip_list'=>['198.51.100.1','2001:db8::1']];
 return ['success'=>true,'snapshot_version'=>1,'observed_at'=>$at,'finished_at'=>$at,'inventory_stable'=>true,'complete'=>true,'names'=>['a','b'],
  'statuses'=>['a'=>$status,'b'=>array_replace($status,['currently_banned'=>1,'banned_ip_list'=>['198.51.100.1']])],
  'targets'=>[['jail'=>'a','ip'=>'198.51.100.1','ticket'=>'identity A'],['jail'=>'a','ip'=>'2001:db8::1','ticket'=>'permanent -1'],['jail'=>'b','ip'=>'198.51.100.1','ticket'=>'identity B']],'errors'=>[]];
}
$d=S::decode(fixture43(),1001);
s43($d['complete']&&$d['tickets']===3&&$d['unique_ips']===2&&$d['jails']===2,'Unique versus jail tickets');
s43($d['identities']['a|198.51.100.1']==='identity A'&&$d['identities']['b|198.51.100.1']==='identity B','Scoped temporal identities');
$r=fixture43();$r['statuses']['a']=null;$r['targets']=[$r['targets'][2]];$r['complete']=false;$r['errors']=['a'];$d=S::decode($r,1001);
s43(!$d['complete']&&$d['tickets']===null&&$d['unique_ips']===null&&$d['online']===true,'Partial not healthy zero');
s43($d['statuses']['a']===null&&$d['identities']===['b|198.51.100.1'=>'identity B'],'Only verified partial data');
$r=fixture43();$r['names']=[];$r['statuses']=[];$r['targets']=[];$d=S::decode($r,1001);
s43($d['complete']&&$d['jails']===0&&$d['tickets']===0&&$d['unique_ips']===0,'Complete empty confirmed');
$bad=[];
foreach(['success'=>false,'snapshot_version'=>0,'observed_at'=>900,'finished_at'=>1002,'complete'=>1,'inventory_stable'=>'true','names'=>null,'statuses'=>null,'targets'=>null,'errors'=>null] as $k=>$v){$r=fixture43();$r[$k]=$v;$bad[]=$r;}
$bad[]=['success'=>false,'error'=>'Unsupported operation'];$bad[]=['success'=>true,'version'=>26];
$r=fixture43();unset($r['statuses']['b']);$bad[]=$r;
$r=fixture43();$r['statuses']['unexpected']=$r['statuses']['a'];$bad[]=$r;
$r=fixture43();$r['names']=['a','a'];$bad[]=$r;
$r=fixture43();$r['names']=['a',"b\n"];$bad[]=$r;
$r=fixture43();$r['names']=array_fill(0,201,'a');$bad[]=$r;
foreach(['currently_banned'=>true,'total_banned'=>-1,'currently_failed'=>'0','total_failed'=>9007199254740992] as $k=>$v){$r=fixture43();$r['statuses']['a'][$k]=$v;$bad[]=$r;}
$r=fixture43();$r['targets'][]=$r['targets'][0];$bad[]=$r;
$r=fixture43();$r['statuses']['a']['banned_ip_list']=['198.51.100.1','198.51.100.1'];$bad[]=$r;
$r=fixture43();$r['targets'][0]['ip']='198.51.100.1/24';$bad[]=$r;
$r=fixture43();$r['targets'][0]['jail']='unknown';$bad[]=$r;
foreach(['',str_repeat('x',201),"new\nline",[],null] as $id){$r=fixture43();$r['targets'][0]['ticket']=$id;$bad[]=$r;}
$r=fixture43();array_pop($r['targets']);$bad[]=$r;
$r=fixture43();$r['statuses']['a']=null;$r['complete']=false;$r['errors']=['a'];$bad[]=$r;
$r=fixture43();$r['complete']=false;$bad[]=$r;
$r=fixture43();$r['errors']=['a'];$bad[]=$r;
$r=fixture43();$r['inventory_stable']=false;$bad[]=$r;
foreach($bad as $i=>$r){$d=S::decode($r,1001);s43(!$d['complete']&&$d['statuses']===[]&&$d['identities']===[]&&$d['unique_ips']===null,'Invalid contract fails closed '.$i);}
$r=fixture43();$r['inventory_stable']=false;$r['complete']=false;$r['statuses']=[];$r['targets']=[];$d=S::decode($r,1001);
s43(!$d['complete']&&$d['jails']===null&&$d['statuses']===[],'Changed inventory not stale targets');
$r=fixture43();$r['statuses']['a']['banned_ip_list'][1]='::ffff:c633:6401';$r['targets'][1]['ip']='::ffff:198.51.100.1';$d=S::decode($r,1001);
s43($d['complete']&&isset($d['identities']['a|::ffff:198.51.100.1']),'Python/PHP mapped IPv6 conventions normalized');
$_SESSION=['adminid'=>1];P::$result=fixture43(time());P::$calls=[];$view=V::read([],[]);
s43(count(P::$calls)===1&&P::$calls[0]===['--read-budget','5','ips-snapshot'],'One grouped native call including identities');
s43(A::ticket($view['rows'][0]['preview'],'198.51.100.1','a')==='identity A','Existing signed action confirmation preserved');
$view=V::read([],['page'=>'2','jail'=>'b']);s43(count(P::$calls)===2&&count($view['rows'])===1,'Pagination/filter one fresh call each; no persistent cache');
P::$fail=true;P::$calls=[];$view=V::read([],[]);
s43(count(P::$calls)===1&&$view['rows']===[]&&!$view['native']['complete'],'Timeout no CLI fallback');
P::$fail=false;P::$result=['success'=>false,'error'=>'Unsupported operation'];P::$calls=[];$view=V::read([],[]);
s43(count(P::$calls)===1&&!$view['native']['complete']&&!$view['open_modal'],'Old helper no slow fallback or manual ban target');
P::$result=fixture43(time());P::$calls=[];$native=D::native([]);
s43(count(P::$calls)===1&&P::$calls[0]===['--read-budget','5','ips-snapshot'],'Dashboard one bounded helper call');
s43($native['complete']&&$native['unique_ips']===2&&$native['tickets']===3&&$native['jails']===2,'Dashboard validated totals');
s43(!array_key_exists('identities',$native)&&isset($native['seconds']),'Dashboard no action identities');
s43($native['statuses']===S::decode(P::$result)['statuses'],'Dashboard all jail counters preserved');
D::native([]);s43(count(P::$calls)===2,'Dashboard refresh no persistent cache');
P::$result=fixture43(time());P::$result['statuses']['a']=null;P::$result['targets']=[P::$result['targets'][2]];P::$result['complete']=false;P::$result['errors']=['a'];
$native=D::native([]);s43(!$native['complete']&&$native['online']===true&&$native['unique_ips']===null&&$native['statuses']['a']===null,'Dashboard partial not zero');
P::$result=fixture43(time());P::$result['inventory_stable']=false;P::$result['complete']=false;P::$result['statuses']=[];P::$result['targets']=[];
$native=D::native([]);s43(!$native['complete']&&$native['jails']===null&&$native['statuses']===[],'Dashboard changing inventory');
P::$result=fixture43(time());P::$result['names']=[];P::$result['statuses']=[];P::$result['targets']=[];
$native=D::native([]);s43($native['complete']&&$native['unique_ips']===0&&$native['jails']===0,'Dashboard confirmed empty');
foreach([['success'=>false,'error'=>'Unsupported operation'],fixture43(time()-60),array_replace(fixture43(time()),['complete'=>'true'])] as $bad){
 P::$result=$bad;P::$calls=[];$native=D::native([]);
 s43(count(P::$calls)===1&&!$native['complete']&&$native['unique_ips']===null&&$native['statuses']===[],'Dashboard unavailable/stale/malformed no fallback');
}
P::$fail=true;P::$calls=[];$native=D::native([]);
s43(count(P::$calls)===1&&!$native['complete']&&$native['jails']===null,'Dashboard timeout no CLI fallback');
echo "PASS: {$checks} grouped IP/dashboard snapshot contract/pagination/identity/failure checks; mocked SQL/native\n";
}
