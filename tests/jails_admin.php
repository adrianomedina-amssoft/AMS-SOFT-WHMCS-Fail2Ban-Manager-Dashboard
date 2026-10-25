<?php
namespace WHMCS\Database {
    class Capsule {
        public static array $queries=[];public static bool $busy=false,$fail=false;
        public static function connection(){if(self::$fail)throw new \RuntimeException('DB offline');return new self;}
        public function selectOne($sql){self::$queries[]=$sql;return (object)['acquired'=>self::$busy?0:1];}
    }
}
namespace AMS\Fail2Ban {
    class Database {public static array $events=[];public static bool $fail=false;public static function logEvent(...$a){if(self::$fail)throw new \RuntimeException('SQL');self::$events[]=$a;}public static function getConfig($k,$d=null){return $d;}}
    class Privileged {
        public static array $names=['a'],$calls=[];public static string $mode='ok';
        public static function run($args){
            self::$calls[]=$args;
            if(array_slice($args,0,4)!==['--read-budget','3','client-read','status'])throw new \RuntimeException('Unexpected command');
            if(self::$mode==='fail'||(self::$mode==='after'&&FixtureConfig::$writes>0))return ['success'=>false];
            if(count($args)===4){
                $names=self::$names;
                if(self::$mode==='changed'&&count(self::$calls)>1)$names[]='extra';
                return ['success'=>true,'output'=>"Number of jail: ".count($names)."\nJail list: ".implode(', ',$names)."\n"];
            }
            if(self::$mode==='malformed')return ['success'=>true,'output'=>'incomplete'];
            return ['success'=>true,'output'=>"Currently failed: 0\nTotal failed: 7\nCurrently banned: 1\nTotal banned: 9\nBanned IP list: 198.51.100.1\n"];
        }
    }
}
namespace {
    if(PHP_SAPI!=='cli')exit(1);
    require dirname(__DIR__).'/lib/Router.php';
    use AMS\Fail2Ban\{JailAdmin as A,Database as D,Privileged as P,JailConfig,Router};
    use WHMCS\Database\Capsule as C;
    $checks=0;function a42($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
}
namespace AMS\Fail2Ban {
    class FixtureConfig extends JailConfig {
        public static int $writes=0;public array $local=[],$effective=[],$last=[];public string $hash='h',$mode='ok';public bool $native=true;public int $reloads=0;
        public function __construct(){$this->effective=['a'=>['enabled'=>'true','filter'=>'sshd','maxretry'=>'5','findtime'=>'10m','bantime'=>'48h','logpath'=>"/var/log/a\n/var/log/b"]];$this->local=$this->effective;}
        public function localHash():string{if($this->mode==='read_fail')throw new \RuntimeException('read');return $this->hash;}
        public function readJailLocal():array{return $this->local;}
        public function readEffective():array{return $this->effective;}
        public function guardUiWrite(string $hash):void{if($hash!==$this->hash)throw new \RuntimeException('Hash');}
        public function appliesOnWrite():bool{return $this->native;}
        public function saveJail(string $jail,array $params):bool {
            self::$writes++;$this->last=$params;
            if($this->mode==='write_fail')return false;
            $this->local[$jail]=array_replace($this->local[$jail]??[],$params);$this->hash.='1';
            if($this->mode!=='override')$this->effective[$jail]=array_replace($this->effective[$jail]??[],$params);
            if($this->mode!=='drift'){
                Privileged::$names=array_values(array_diff(Privileged::$names,[$jail]));
                if(JailAdmin::enabled($this->effective[$jail]??[]))Privileged::$names[]=$jail;
                sort(Privileged::$names);
            }
            return true;
        }
        public function addJail(string $jail,array $params):bool{return $this->saveJail($jail,$params);}
        public function removeJail(string $jail):bool{
            self::$writes++;unset($this->local[$jail]);$this->hash.='1';
            if($this->mode!=='inherited'){unset($this->effective[$jail]);Privileged::$names=array_values(array_diff(Privileged::$names,[$jail]));}
            return true;
        }
        public function reloadAll():bool{$this->reloads++;return $this->mode!=='reload_fail';}
    }
}
namespace {
    use AMS\Fail2Ban\{JailAdmin as A,Database as D,Privileged as P,FixtureConfig as F,Router};
    use WHMCS\Database\Capsule as C;
    function reset42(){F::$writes=0;P::$names=['a'];P::$calls=[];P::$mode='ok';D::$events=[];D::$fail=false;C::$queries=[];C::$busy=C::$fail=false;$_SESSION=['adminid'=>1,'amssoft_fail2ban_csrf'=>'csrf'];$_SERVER['REQUEST_METHOD']='POST';return new F;}
    function post42($c,$j='a',$add=false){return ['csrf_token'=>'csrf','confirm'=>'1','jail'=>$j,'new_jail'=>$j,'preview'=>A::preview(A::snapshot($c),$add?'@add':$j),'enabled'=>'1','maxretry'=>'5','findtime'=>'10m','bantime'=>'48h','logpath'=>"/var/log/a\r\n/var/log/b",'filter'=>'sshd'];}
    $c=reset42();$s=A::snapshot($c);$t=A::preview($s,'a',1000);
    a42(A::valid($t,$s,'a',1899),'Preview valid');
    foreach([999,1900,3000] as $at)a42(!A::valid($t,$s,'a',$at),'Preview time refused');
    a42(!A::valid($t,$s,'b',1001),'Preview bound to target');
    a42(!A::valid($t.'x',$s,'a',1001),'Tamper refused');
    $s['digest']='changed';a42(!A::valid($t,$s,'a',1001),'Config fingerprint bound');
    $_SESSION['amsfb_jails_key']='other';a42(!A::valid($t,A::snapshot($c),'a',1001),'Session bound');
    foreach([[],null,"a\n",'-h','DEFAULT','INCLUDES','a/b',str_repeat('a',65)] as $v)a42(A::name($v)==='','Invalid jail scalar/name refused');
    $c=reset42();$post=post42($c);
    a42(A::parameters($post,$c->effective['a'],false)===[],'Units and multiline CRLF retained without changes');
    $post['bantime']='-1';a42(A::parameters($post,$c->effective['a'],false)===['bantime'=>'-1'],'Permanent duration');
    $post=post42($c);$post['findtime']='3600';a42(A::parameters($post,$c->effective['a'],false)===['findtime'=>'3600'],'Explicit seconds');
    foreach([['maxretry'=>[]],['findtime'=>'0'],['findtime'=>'20m'],['bantime'=>'-2'],['bantime'=>'999999999'],['enabled'=>[]],['logpath'=>[]],['logpath'=>''],['logpath'=>"/var/log/new\n/var/log/second"],['logpath'=>"/var/log/a\n[evil]"],['logpath'=>'/etc/passwd'],['logpath'=>'/var/log/../etc'],['logpath'=>'/var/log/%(x)s']] as $bad){
        try{A::parameters(array_replace(post42($c),$bad),$c->effective['a'],false);a42(false,'Malformed values accepted');}catch(InvalidArgumentException $e){a42(true,'Malformed fields denied');}
    }
    foreach([['csrf_token'=>[]],['csrf_token'=>'wrong'],['confirm'=>[]],['confirm'=>'0'],['jail'=>[]],['preview'=>[]],['preview'=>''],['jail'=>'DEFAULT']] as $bad){
        $c=reset42();$r=A::execute('disable',array_replace(post42($c),$bad),$c);a42(!$r['success']&&F::$writes===0,'Invalid request no writes');
    }
    $c=reset42();$p=post42($c);$_SERVER['REQUEST_METHOD']='GET';a42(!A::execute('disable',$p,$c)['success']&&P::$calls===[],'GET refused');
    $c=reset42();$p=post42($c);$_SESSION['adminid']=0;a42(!A::execute('disable',$p,$c)['success']&&P::$calls===[],'Unauthenticated refused');
    $c=reset42();a42(!A::execute('reload_all',post42($c),$c)['success']&&F::$writes===0,'Hidden arbitrary reload refused');
    $c=reset42();$p=post42($c);$c->hash='other';a42(!A::execute('disable',$p,$c)['success']&&F::$writes===0,'Stale page no write');
    foreach(['read_fail','write_fail','override','drift'] as $mode){
        $c=reset42();$p=post42($c);$c->mode=$mode;$r=A::execute('disable',$p,$c);
        a42(!$r['success']&&D::$events===[],'No false success or audit: '.$mode);
    }
    foreach(['fail','after','malformed'] as $mode){
        $c=reset42();$p=post42($c);$p['bantime']='3600';P::$mode=$mode;$r=A::execute('save',$p,$c);
        a42(!$r['success']&&D::$events===[],'Native failure not success: '.$mode);
    }
    $c=reset42();$r=A::execute('disable',post42($c),$c);
    a42($r['success']&&D::$events[0][2]==='jail_disabled'&&$c->reloads===0,'Single native install no duplicate reload');
    a42(count(array_filter(C::$queries,fn($q)=>str_contains($q,'RELEASE_LOCK')))===2,'Both locks released');
    $c=reset42();$r=A::execute('save',post42($c),$c);a42($r['success']&&F::$writes===0&&D::$events===[],'Unchanged form no write/reload/audit');
    $c=reset42();$r=A::execute('enable',post42($c),$c);a42($r['success']&&F::$writes===0,'Already enabled not renewed');
    $c=reset42();$p=post42($c);$p['bantime']='3600';$r=A::execute('save',$p,$c);a42($r['success']&&$c->last===['bantime'=>'3600'],'Only requested field written');
    $c=reset42();$c->mode='inherited';$r=A::execute('remove',post42($c),$c);a42($r['success']&&str_contains($r['message'],'herdado: habilitada')&&P::$names===['a'],'Removal reports inherited active jail');
    $c=reset42();$c->local=[];$r=A::execute('remove',post42($c),$c);a42(!$r['success']&&F::$writes===0,'No removal of default/jail.d');
    $c=reset42();$p=post42($c,'a',true);a42(!A::execute('add',$p,$c)['success']&&F::$writes===0,'No duplicate native jail');
    $c=reset42();$p=post42($c,'new',true);$p['findtime']='600';$p['bantime']='-1';$p['logpath']='/var/log/auth.log';
    $r=A::execute('add',$p,$c);a42($r['success']&&isset($c->effective['new'])&&$c->reloads===0,'Creation uses existing validated filter/native install');
    $c=reset42();$p=post42($c);$c->native=false;$c->mode='reload_fail';a42(!A::execute('disable',$p,$c)['success']&&D::$events===[],'Non-native file reload failure never successful');
    $c=reset42();D::$fail=true;ini_set('error_log','/dev/null');$r=A::execute('disable',post42($c),$c);a42($r['success']&&$r['warning']&&!$r['audit_recorded'],'Audit failure distinct from successful mutation');
    $c=reset42();C::$busy=true;a42(!A::execute('disable',post42($c),$c)['success']&&F::$writes===0,'Busy cycle fail closed');
    $c=reset42();C::$fail=true;a42(!A::execute('disable',post42($c),$c)['success']&&F::$writes===0,'DB unavailable before write');
    $c=reset42();$router=new Router([]);$r=json_decode($router->handleAjax('jails','disable',['csrf_token'=>[]]),true);a42(!$r['success']&&F::$writes===0,'Router malformed CSRF');
    // Read model: only visible loaded jail counters are queried.
    $c=reset42();$c->effective=[];for($i=0;$i<25;$i++)$c->effective[sprintf('j%02d',$i)]=['enabled'=>'true'];P::$names=array_keys($c->effective);
    $v=A::view($c,['page'=>'2']);a42(count($v['selection']['rows'])===10&&$v['selection']['rows'][0]==='j10','Stable paging');
    a42(count(P::$calls)===12&&count($v['statuses'])===10,'Only page counters plus two list reads');
    a42($v['selection']['loaded']===25&&$v['selection']['configured']===25,'Separate counts');
    $v=A::select(A::snapshot($c),null,['q'=>[],'page'=>[],'state'=>[]]);a42($v['error']!==null&&$v['page']===1&&$v['loaded']===null,'Malformed filter and unknown daemon');
    $v=A::select(A::snapshot($c),P::$names,['q'=>'j24','page'=>'999']);a42($v['rows']===['j24']&&$v['page']===1,'Filtered page clamp');
    $v=A::select(A::snapshot($c),P::$names,['state'=>'disabled']);a42($v['rows']===[],'Disabled filter accurate');
    $v=A::select(A::snapshot($c),['runtime-only'],['q'=>'runtime']);a42($v['rows']===['runtime-only'],'Runtime-only jail visible');
    $c=reset42();P::$mode='fail';$v=A::view($c,[]);a42($v['names']===null&&$v['selection']['loaded']===null&&$v['previews']===[],'Failure not offline/zero; actions withheld');
    $c=reset42();P::$mode='malformed';$v=A::view($c,[]);a42($v['statuses']['a']===null&&!empty($v['errors']),'Malformed counters not zero');
    $c=reset42();P::$mode='changed';$v=A::view($c,[]);a42($v['names']===null&&$v['previews']===[],'Changing inventory withheld');
    $c=reset42();$c->mode='read_fail';$v=A::view($c,[]);a42($v['snapshot']===null&&$v['selection']['rows']===['a']&&$v['previews']===[],'Config failure still shows runtime inventory without mutation');
    echo "PASS: {$checks} jail actions and read-model checks; simulated writes/native/SQL\n";
}
