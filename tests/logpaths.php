<?php
namespace WHMCS\Database {
class Capsule {
    public static array $rows=[];public static bool $fail=false,$lock=true,$zeroDelete=false;public static int $writes=0;
    public static function table($t){if(self::$fail)throw new \RuntimeException('SQL fixture');return new Query;}
    public static function connection(){return new self;}
    public function selectOne($sql){return (object)['acquired'=>self::$lock?1:0];}
    public function transaction($f){$before=self::$rows;$events=\AMS\Fail2Ban\Database::$events;try{return $f();}catch(\Throwable $e){self::$rows=$before;\AMS\Fail2Ban\Database::$events=$events;throw $e;}}
}
class Query {
    private array $filters=[];private int $offset=0,$limit=100000;
    public function whereRaw($sql,$args){if($sql!=="`key` LIKE ? ESCAPE '='"||$args!==['custom=_log.%'])throw new \RuntimeException('Unexpected prefix query');$this->filters[]=fn($r)=>str_starts_with($r['key'],'custom_log.');return $this;}
    public function where($k,$v){$this->filters[]=fn($r)=>$r[$k]===$v;return $this;}
    public function orderBy($k){return $this;}public function lockForUpdate(){return $this;}
    public function offset($n){$this->offset=$n;return $this;}public function limit($n){$this->limit=$n;return $this;}
    private function selected(){return array_filter(Capsule::$rows,fn($r)=>!array_filter($this->filters,fn($f)=>!$f($r)));}
    public function count(){return count($this->selected());}
    public function get(){return array_map(fn($r)=>(object)$r,array_slice(array_values($this->selected()),$this->offset,$this->limit));}
    public function first(){return $this->get()[0]??null;}
    public function insert($row){Capsule::$writes++;$row['id']=1+max([0,...array_column(Capsule::$rows,'id')]);Capsule::$rows[]=$row;return true;}
    public function delete(){if(Capsule::$zeroDelete)return 0;$keys=array_keys($this->selected());foreach($keys as $k)unset(Capsule::$rows[$k]);Capsule::$writes++;return count($keys);}
}
}
namespace AMS\Fail2Ban {
class Database {public static array $events=[];public static bool $fail=false;public static function logEvent(...$a){if(self::$fail)throw new \RuntimeException('Audit failed');self::$events[]=$a;}}
class PathFixture {public static array $files=[],$calls=[];}
function realpath($p){PathFixture::$calls[]=$p;return PathFixture::$files[$p]['real']??false;}
function is_file($p){return (PathFixture::$files[$p]['type']??'file')==='file'&&isset(PathFixture::$files[$p]);}
function is_readable($p){return PathFixture::$files[$p]['readable']??true;}
function filesize($p){return PathFixture::$files[$p]['size']??0;}
function is_dir($p){return $p==='/var/log'||$p==='/var/log/fixture'||(PathFixture::$files[$p]['type']??'')==='dir';}
function is_executable($p){return true;}
function is_link($p){return PathFixture::$files[$p]['link']??false;}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);ini_set('error_log','/dev/null');require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{LogPaths as L,PathFixture as F,Database as D,Helper,Router};use WHMCS\Database\Capsule as C;
$checks=0;function lp($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
function resetLP(){C::$rows=[];C::$writes=0;C::$fail=false;C::$lock=true;C::$zeroDelete=false;D::$events=[];D::$fail=false;F::$calls=[];F::$files=[];foreach(['a.log','b.log','no.txt','bad.php','rot.log.1'] as $p){$p='/var/log/fixture/'.$p;F::$files[$p]=['real'=>$p,'readable'=>!str_ends_with($p,'no.txt'),'size'=>25];}$_SESSION=['adminid'=>7,'amssoft_fail2ban_csrf'=>'csrf'];$_SERVER['REQUEST_METHOD']='POST';}
function addLP($p=[]){return L::execute('add',array_replace(['csrf_token'=>'csrf','label'=>'Meu App','path'=>'/var/log/fixture/a.log'],$p));}
resetLP();foreach([null,[],1,'/etc/passwd','/var/log/../etc/a.log',"/var/log/a\n.log",'/var/log//a.log',str_repeat('a',501),"/var/log/\xff.log"] as $bad){$n=count(F::$calls);$r=L::inspect($bad);lp(!$r['valid']&&$r['size']===null&&count(F::$calls)===$n,'Invalid input refused before filesystem');}
lp(L::inspect('/var/log/fixture/a.log')['valid'],'Allowed regular log');lp(L::inspect('/var/log/fixture/rot.log.1')['valid'],'Numeric rotation');
lp(L::inspect('/var/log/fixture/no.txt')['status']==='unreadable','Unreadable distinct');lp(L::inspect('/var/log/fixture/missing.log')['status']==='missing','Confirmed missing');
lp(L::inspect('/var/log/unavailable/missing.log')['status']==='unknown','Unconfirmed parent');lp(L::inspect('/var/log/fixture/bad.php')['status']==='blocked','Extension policy');
F::$files['/var/log/fixture/folder']=['real'=>'/var/log/fixture/folder','type'=>'dir'];lp(L::inspect('/var/log/fixture/folder')['status']==='not_file','Directory rejected');
F::$files['/var/log/fixture/out.log']=['real'=>'/etc/passwd','link'=>true];lp(L::inspect('/var/log/fixture/out.log')['status']==='blocked','Escaping symlink rejected');
F::$files['/var/log/fixture/link.log']=['real'=>'/var/log/fixture/a.log','link'=>true];lp(L::inspect('/var/log/fixture/link.log')['canonical']==='/var/log/fixture/a.log','Internal alias allowed');
F::$files['/var/log/fixture/broken.log']=['link'=>true];lp(L::inspect('/var/log/fixture/broken.log')['status']==='unknown','Broken link not proven absent');
F::$files['/var/log/fixture/a.log']['size']=false;lp(L::inspect('/var/log/fixture/a.log')['size']===null,'Unknown size not zero');
lp(L::key('Meu App')==='meu-app','Explicit identifier normalization');foreach(['',[],"A\n",'Árvore','<x>','-x',str_repeat('x',65)] as $v)lp(L::key($v)===null,'Invalid name not sanitized');
resetLP();$r=addLP();lp($r['success']&&C::$rows[0]['key']==='custom_log.meu-app'&&count(D::$events)===1,'Insert and audit confirmed');
$before=C::$rows;lp(!addLP(['path'=>'/var/log/fixture/b.log'])['success']&&C::$rows===$before,'No overwrite');
lp(!addLP(['label'=>'Outro'])['success'],'Duplicate path refused');F::$files['/var/log/fixture/link.log']=['real'=>'/var/log/fixture/a.log','link'=>true];lp(!addLP(['label'=>'Alias','path'=>'/var/log/fixture/link.log'])['success'],'Canonical duplicate refused');
resetLP();$r=addLP(['path'=>'/var/log/fixture/no.txt']);lp($r['success']&&$r['warning'],'Unreadable registration explicit warning');
resetLP();F::$files['/var/log/fail2ban.log']=['real'=>'/var/log/fail2ban.log'];lp(!addLP(['path'=>'/var/log/fail2ban.log'])['success']&&C::$writes===0,'Built-in duplicate refused');
foreach([['csrf_token'=>[]],['csrf_token'=>'bad'],['label'=>[]],['path'=>[]],['label'=>'<x>']] as $bad){resetLP();lp(!addLP($bad)['success']&&C::$writes===0,'Malformed/refused request no write');}
resetLP();$_SESSION['adminid']=0;lp(!addLP()['success']&&C::$writes===0,'Unauthenticated');resetLP();$_SERVER['REQUEST_METHOD']='GET';lp(!addLP()['success'],'GET refuses mutation');
resetLP();C::$lock=false;lp(!addLP()['success']&&C::$writes===0,'Concurrent writer denied');resetLP();C::$fail=true;lp(!addLP()['success']&&C::$rows===[],'SQL failure not success');
resetLP();D::$fail=true;lp(!addLP()['success']&&C::$rows===[]&&D::$events===[],'Audit failure rolls registration back');
resetLP();for($i=1;$i<=500;$i++)C::$rows[]=['id'=>$i,'key'=>'custom_log.x'.$i,'value'=>'/var/log/x'.$i.'.log'];lp(!addLP()['success']&&count(C::$rows)===500,'Bounded registrations');
resetLP();addLP();$row=C::$rows[0];$token=L::preview($row,1000);lp(L::matches($token,$row,1899),'Preview lifetime');
foreach([999,1900] as $now)lp(!L::matches($token,$row,$now),'Future/expired preview');foreach(['id'=>9,'key'=>'custom_log.other','value'=>'/var/log/fixture/b.log'] as $k=>$v)lp(!L::matches($token,array_replace($row,[$k=>$v]),1001),'Identity/version mismatch');
lp(!L::matches($token.'x',$row,1001),'Tamper refused');$_SESSION['adminid']=8;lp(!L::matches($token,$row,1001),'Admin binding');$_SESSION['adminid']=7;unset($_SESSION['amsfb_logpaths_key']);lp(!L::matches($token,$row,1001),'Session binding');
$post=['csrf_token'=>'csrf','id'=>'1','preview'=>L::preview($row),'confirm'=>'1'];$r=L::execute('delete',$post);lp($r['success']&&C::$rows===[]&&count(D::$events)===2,'Scoped delete confirmed');lp(!L::execute('delete',$post)['success'],'Replay not false success');
resetLP();addLP();$post=['csrf_token'=>'csrf','id'=>'1','preview'=>L::preview(C::$rows[0]),'confirm'=>'1'];C::$rows[0]['value']='/var/log/fixture/b.log';lp(!L::execute('delete',$post)['success']&&count(C::$rows)===1,'Stale page preserves changed registration');
$post['preview']=L::preview(C::$rows[0]);C::$zeroDelete=true;lp(!L::execute('delete',$post)['success']&&count(C::$rows)===1,'Affected count checked');C::$zeroDelete=false;D::$fail=true;lp(!L::execute('delete',$post)['success']&&count(C::$rows)===1,'Audit failure rolls deletion back');
resetLP();C::$rows=[['id'=>1,'key'=>'ai_auto_enabled','value'=>'1']];$p=['csrf_token'=>'csrf','id'=>'1','preview'=>L::preview(C::$rows[0]),'confirm'=>'1'];lp(!L::execute('delete',$p)['success']&&C::$rows[0]['value']==='1','Cannot delete nonregistration config');
resetLP();for($i=1;$i<=23;$i++)C::$rows[]=['id'=>$i,'key'=>'custom_log.x'.$i,'value'=>'/var/log/missing'.$i.'.log'];C::$rows[]=['id'=>24,'key'=>'customXlog.secret','value'=>'hidden'];
$v=L::read(['page'=>'2']);lp($v['total']===23&&count($v['custom'])===10&&$v['page']===2,'Literal prefix and pagination');$v=L::read(['page'=>'99']);lp($v['page']===3&&count($v['custom'])===3,'Page clamped');lp(L::read(['page'=>[]])['page']===1,'Malformed page safe');
lp(C::$writes===0,'GET no writes');C::$fail=true;$v=L::read([]);lp($v['total']===null&&$v['error']&&$v['custom']===[],'SQL unavailable not empty');
resetLP();$router=new Router([]);$r=json_decode($router->handleAjax('logpaths','validate',['csrf_token'=>'csrf','path'=>'/etc/passwd']),true);lp($r['success']&&!$r['valid']&&$r['exists']===null,'Actual AJAX denies metadata outside policy');
lp(!json_decode($router->handleAjax('logpaths','add',['csrf_token'=>'csrf']),true)['success'],'No AJAX mutations');
$view=L::read([]);$view['custom']=[['id'=>1,'label'=>'</script><img src=x onerror=alert(1)>','path'=>'/var/log/<bad>.log','preview'=>'signed']+L::inspect(null)];$view['total']=1;
$modulelink='addonmodules.php?module=amssoft_fail2ban';$asset_base='/assets';$csrf_token='csrf';$e=fn($v)=>Helper::e($v);ob_start();include dirname(__DIR__).'/templates/logpaths_overview.tpl';$html=ob_get_clean();
lp(!str_contains($html,'<img src=x')&&!str_contains($html,'onsubmit='),'Escaped template no inline handlers');lp(str_contains($html,'name="confirm"')&&str_contains($html,'name="preview"'),'Server confirmation fields');
lp(str_contains($html,'não medido')&&str_contains($html,'não confirma seleção'),'Unknown/scope explained');
echo "PASS: {$checks} log paths metadata/auth/transaction/identity/pagination/render checks; mocked SQL/filesystem, no native or provider\n";
}
