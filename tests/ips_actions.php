<?php
namespace AMS\Fail2Ban {
class Database {
    public static array $events=[];public static bool $fail=false;
    public static function getConfig($k,$d=null){return $d;}
    public static function logEvent(...$args){if(self::$fail)throw new \RuntimeException('fixture');self::$events[]=$args;}
}
class AutoBanEngine {public static array $whitelist=[];public static function loadWhitelist(){return self::$whitelist;}}
class Privileged {
    public static array $ips=[],$calls=[];public static string $mode='ok';public static bool $applied=true;
    public static function run($args){
        self::$calls[]=$args;$jail=$args[count($args)-1];
        if(array_slice($args,0,4)===['--read-budget','3','client-read','status']){
            if(self::$mode==='read_fail'||(self::$mode==='after_fail'&&count(self::$calls)>2))return ['success'=>false];
            if(self::$mode==='malformed')return ['success'=>true,'output'=>'error no jail'];
            $ips=self::$ips[$jail]??[];
            return ['success'=>true,'output'=>"Currently failed: 0\nTotal failed: 0\nCurrently banned: ".count($ips)."\nTotal banned: 1\nBanned IP list: ".implode(' ',$ips)."\n"];
        }
        if($args[0]==='unban-ticket'){
            if(self::$mode==='command_fail')return ['success'=>false];
            if(self::$mode==='renewed')return ['success'=>true,'skipped'=>true];
            if(self::$mode!=='reban')self::$ips[$args[1]]=array_values(array_diff(self::$ips[$args[1]],[$args[2]]));
            return ['success'=>true,'skipped'=>self::$mode==='expired'];
        }
        if($args[0]==='ban'){self::$ips[$args[1]][]=$args[2];return ['success'=>true];}
        if($args[0]==='check-ban')return ['success'=>true,'applied'=>self::$applied];
        throw new \RuntimeException('Unexpected native command');
    }
}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{IpBanActions as A,Privileged as P,Database as D,Fail2BanClient,AutoBanEngine,Router};
$checks=0;function a41($ok,$why){global $checks;if(!$ok)throw new RuntimeException($why);$checks++;}
function reset41(){P::$ips=['a'=>['198.51.100.1'],'b'=>['198.51.100.1']];P::$calls=[];P::$mode='ok';P::$applied=true;D::$events=[];D::$fail=false;AutoBanEngine::$whitelist=[];$_SESSION=['adminid'=>7,'amssoft_fail2ban_csrf'=>'csrf'];$_SERVER['REQUEST_METHOD']='POST';}
reset41();$client=new Fail2BanClient('/unused','/unused');
$token=A::preview('198.51.100.1','a','fixture ticket',1000);
a41(A::ticket($token,'198.51.100.1','a',1899)==='fixture ticket','Preview valid within 15m');
foreach([['198.51.100.1','a',1900],['198.51.100.1','a',999],['198.51.100.2','a',1001],['198.51.100.1','b',1001]] as $args)a41(A::ticket($token,...$args)===null,'Expired/future/scope mismatch rejected');
a41(A::ticket($token.'x','198.51.100.1','a',1001)===null,'Tampered HMAC');
$saved=$_SESSION['amsfb_ips_preview_key'];unset($_SESSION['amsfb_ips_preview_key']);a41(A::ticket($token,'198.51.100.1','a',1001)===null,'Other session denied');$_SESSION['amsfb_ips_preview_key']=$saved;
foreach(["bad\nticket",str_repeat('x',201),''] as $ticket)a41(A::ticket(A::preview('198.51.100.1','a',$ticket),'198.51.100.1','a')===null,'Malformed identity denied');
function post41(){return ['csrf_token'=>'csrf','ip'=>'198.51.100.1','jail'=>'a','preview'=>A::preview('198.51.100.1','a','fixture ticket')];}
foreach(['read_fail','malformed','command_fail','renewed','reban','after_fail'] as $mode){reset41();P::$mode=$mode;$r=A::execute('unban',post41(),$client);a41(!$r['success']&&D::$events===[],'Unconfirmed unban never successful/logged: '.$mode);}
reset41();$r=A::execute('unban',post41(),$client);a41($r['success']&&$r['audit_recorded']&&D::$events[0][2]==='manual_unban','Confirmed scoped unban audited');
a41(P::$ips['a']===[]&&P::$ips['b']===['198.51.100.1'],'Other jail unaffected');
$r=A::execute('unban',post41(),$client);a41($r['state']==='already_absent'&&count(D::$events)===1,'Absent not logged as another manual unban');
reset41();P::$mode='expired';$r=A::execute('unban',post41(),$client);a41($r['success']&&$r['state']==='already_absent'&&D::$events===[],'Expired ticket not attributed to action');
reset41();$p=post41();unset($p['preview']);a41(!A::execute('unban',$p,$client)['success']&&P::$calls===[],'Legacy stale button denied before native call');
foreach([['ip'=>[]],['jail'=>[]],['csrf_token'=>[]],['csrf_token'=>'bad'],['jail'=>'-bad'],['ip'=>'198.51.100.1/24']] as $bad){reset41();$p=array_replace(post41(),$bad);a41(!A::execute('unban',$p,$client)['success']&&P::$calls===[],'Malformed inputs denied before native call');}
reset41();$p=post41();$_SERVER['REQUEST_METHOD']='GET';a41(!A::execute('unban',$p,$client)['success']&&P::$calls===[],'GET never mutates');
reset41();$p=post41();$_SESSION['adminid']=0;a41(!A::execute('unban',$p,$client)['success']&&P::$calls===[],'No admin denied');
reset41();a41(!A::execute('reload',post41(),$client)['success']&&P::$calls===[],'Unknown action denied');
reset41();$r=A::execute('ban',post41(),$client);a41($r['state']==='already_present'&&count(P::$calls)===1&&D::$events===[],'Existing ban not renewed');
reset41();P::$ips['a']=[];$r=A::execute('ban',post41(),$client);a41($r['success']&&D::$events[0][2]==='manual_ban','Confirmed ban recorded');
reset41();P::$ips['a']=[];$p=post41();$p['ip']='2001:0db8:0:0:0:0:0:1';$r=A::execute('ban',$p,$client);a41($r['success']&&P::$ips['a']===['2001:db8::1'],'IPv6 canonical ban with real client guard');
foreach(['127.0.0.1','::1','::ffff:127.0.0.1','0.0.0.0'] as $ip){reset41();P::$ips['a']=[];$p=post41();$p['ip']=$ip;$r=A::execute('ban',$p,$client);a41(!$r['success']&&count(P::$calls)===1&&D::$events===[],'Protected IP real client guard: '.$ip);}
reset41();P::$ips['a']=[];AutoBanEngine::$whitelist=['198.51.100.0/24'];a41(!A::execute('ban',post41(),$client)['success']&&count(P::$calls)===1,'Whitelist preserved');
reset41();P::$ips['a']=[];P::$applied=false;a41(!A::execute('ban',post41(),$client)['success']&&D::$events===[],'No audit without effective ban');
reset41();D::$fail=true;ini_set('error_log','/dev/null');$r=A::execute('unban',post41(),$client);a41($r['success']&&$r['warning']&&!$r['audit_recorded']&&$r['state']==='confirmed_audit_failed','Audit failure does not pretend command failed');
reset41();$router=new Router([]);$r=json_decode($router->handleAjax('ips','unban',['csrf_token'=>[]]),true);a41(!$r['success']&&str_contains($r['error'],'CSRF')&&P::$calls===[],'Router rejects array CSRF without TypeError');
$r=json_decode($router->handleAjax('ips','unban',post41()),true);a41($r['success']&&($_SESSION['amssoft_fail2ban_flash']['type']??null)==='success','Actual AJAX controller persists result flash for GET refresh');
echo "PASS: {$checks} IP action authorization/ticket/race/audit/real-client guards; simulated native and SQL\n";
}
