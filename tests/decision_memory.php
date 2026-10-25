<?php
namespace AMS\Fail2Ban;
if (PHP_SAPI!=='cli') exit(1);

// No WHMCS bootstrap, connection, provider or host writes in this suite.
class Database {
    public static array $cfg=[];
    public static function getConfig($key,$default=''){return self::$cfg[$key]??$default;}
}
class Policy {
    public static array $policy=['other_policy'=>'original'];
    public static function values(): array {return self::$policy;}
}
class AIAnalyzer { public const RECOVERY_GENERATION='test-regex-generation'; }
require dirname(__DIR__).'/lib/Safety.php';
require dirname(__DIR__).'/lib/AttackFamily.php';
require dirname(__DIR__).'/lib/BehaviorStore.php';
require dirname(__DIR__).'/lib/DecisionMemory.php';
$checks=0;
function check($ok,$label): void {global $checks;if(!$ok)throw new \RuntimeException('FAIL: '.$label);$checks++;}
function event(string $line,int $index=1): array {
    return ['id'=>hash('sha256','event:'.$index),'line'=>$line,'ip'=>Safety::sourceIp($line),
        'pattern'=>BehaviorStore::pattern($line),'time'=>BehaviorStore::eventTime($line)];
}
function row(array $lines): array {
    $events=[];foreach($lines as $i=>$line)$events[]=event($line,$i+1);
    return ['id'=>hash('sha256','row'),'revision'=>'1','ip'=>$events[0]['ip'],
        'source_log'=>'/var/log/apache2/access.log','pattern'=>$events[0]['pattern'],
        'bucket'=>date('Y-m-d H:i:s',(int)(floor(time()/600)*600)),
        'events'=>(string)count($events),'samples'=>json_encode($events)];
}
$line='198.51.100.246 - alice [14/Oct/2026:12:00:00 -0300] "GET /clientarea.php?a=1 HTTP/1.1" 200 100 "https://example.test/" "Mozilla/5.0"';
$hash=DecisionMemory::lineSignature($line);
check(is_string($hash)&&strlen($hash)===64,'complete access accepted');
check($hash===DecisionMemory::lineSignature($line,'198.51.100.246'),'optional peer uses same feature hash');
check(DecisionMemory::lineSignature($line,'198.51.100.247')===null,'cannot borrow peer');
check(DecisionMemory::lineSignature(str_replace('12:00:00','13:12:19',$line))===$hash,'only timestamp removed');
foreach (['GET'=>'HEAD','?a=1'=>'?a=2','HTTP/1.1'=>'HTTP/2.0','200 100'=>'201 100',
    '200 100'=>'200 101','alice'=>'bob','https://example.test/'=>'https://other.test/','Mozilla/5.0'=>'Other/1.0'] as $from=>$to)
    check(DecisionMemory::lineSignature(str_replace($from,$to,$line))!==$hash,'feature preserved '.$from);
foreach (['POST','PUT','PATCH','DELETE','OPTIONS','CONNECT','TRACE'] as $method)
    check(DecisionMemory::lineSignature(str_replace('GET',$method,$line))===null,'unlogged body/method '.$method);
foreach (['prefix '.$line,$line.' trailing',$line."\n",substr($line,0,-1),
    str_replace('14/Oct','32/Oct',$line),str_replace(' HTTP/1.1','',$line),
    str_replace(' 200 100',' 200',$line),str_replace('Mozilla/5.0',"bad\0UA",$line),
    str_replace('Mozilla/5.0',"bad\xffUA",$line),
    '2026-10-14 12:00:00 WHMCS login failed from 198.51.100.246 area=client',
    '[Wed Oct 14 12:00:00 2026] [client 198.51.100.246] error'] as $bad)
    check(DecisionMemory::lineSignature($bad)===null,'partial/unknown/control access rejected');
foreach (['/.env','/.git/config','/wp-login.php','/x?a=union%20select','/x?a=../etc/passwd'] as $target)
    check(DecisionMemory::lineSignature(str_replace('/clientarea.php?a=1',$target,$line))===null,'known attack '.$target);
$r=row([$line]);$signature=DecisionMemory::signature($r);
check($signature!==null,'complete row accepted');
$r['events']=6;check(DecisionMemory::signature($r)===null,'last-five/partial coverage cannot cache');
$r['behavior_complete']=1;$r['behavior_variants']=json_encode([$hash]);
check(DecisionMemory::signature($r)===$signature,'persistent full set restores coverage');
$variant=str_replace('?a=1','?a=2',$line);$hash2=DecisionMemory::lineSignature($variant);
$r['behavior_variants']=[$hash,$hash2];$full=DecisionMemory::signature($r);
check($full!==null&&$full!==$signature,'missing raw variant retained in persistent identity');
$r['behavior_variants']=[$hash2,$hash];check(DecisionMemory::signature($r)===$full,'persistent set sorted');
foreach ([[],[$hash,$hash],['bad'],array_fill(0,17,$hash),[$hash2]] as $bad) {
    $r['behavior_variants']=$bad;check(DecisionMemory::signature($r)===null,'bad/full set mismatch rejected');
}
$r=row([$line,$variant]);$both=DecisionMemory::signature($r);
$samples=json_decode($r['samples'],true);$r['samples']=array_reverse($samples);
check(DecisionMemory::signature($r)===$both,'all original variants sorted');
$r=row([$line,str_replace('12:00:00','13:00:00',$line)]);
check(DecisionMemory::signature($r)===$signature,'event multiplicity does not affect variant identity');
$r['samples']=[event($line),event($line)];check(DecisionMemory::signature($r)===null,'duplicate event IDs cannot claim full coverage');
foreach (['source_log'=>'/var/log/apache2/error.log','pattern'=>hash('sha256','other'),
    'ip'=>'198.51.100.247','family_key'=>'env-exposure','truncated'=>true,'samples'=>'not-json'] as $field=>$value) {
    $r=row([$line]);$r[$field]=$value;check(DecisionMemory::signature($r)===null,'invalid subject '.$field);
}
$r=row([$line]);$r['source_log']='/var/log/apache2/access_whmcs.log';
check(DecisionMemory::signature($r)!==$signature,'source explicitly scoped');
$r=row([$line]);$r['family_key']='pattern:'.$r['pattern'];
check(DecisionMemory::signature($r)===$signature,'non-threat pattern metadata allowed');
check(!DecisionMemory::enabled(),'off before schema');Database::$cfg=['schema_version'=>'22','ai_reuse_enabled'=>'1'];
check(!DecisionMemory::enabled(),'schema22 disabled');Database::$cfg['schema_version']='23';
check(DecisionMemory::enabled(),'schema23 opt-in');
$fingerprint=DecisionMemory::policyFingerprint();Policy::$policy['other_policy']='changed';
check(DecisionMemory::policyFingerprint()!==$fingerprint,'entire policy invalidates');
$fingerprint=DecisionMemory::policyFingerprint();Database::$cfg['ai_reuse_minutes']='240';
check(DecisionMemory::policyFingerprint()!==$fingerprint,'reuse knobs participate before Policy catalogue updated');
$r=row([$line]);$r['events']=6;
check(!DecisionMemory::reusable($r),'incomplete row miss without repository access');
DecisionMemory::remember($r,[],1);
$settings=new \ReflectionMethod(DecisionMemory::class,'settings');
Database::$cfg['ai_reuse_sample_percent']='0';
check($settings->invoke(null)===null,'zero sampling rejected by settings');
check(!DecisionMemory::reusable(row([$line])),'zero sampling fails closed before repository access');
Database::$cfg['ai_reuse_sample_percent']='1';
check($settings->invoke(null)['ai_reuse_sample_percent']===1,'UI sampling lower bound accepted');
Database::$cfg['ai_reuse_sample_percent']='100';
check($settings->invoke(null)['ai_reuse_sample_percent']===100,'UI sampling upper bound accepted');
Database::$cfg['ai_reuse_sample_percent']='101';
check($settings->invoke(null)===null,'sampling above UI upper bound rejected');
foreach (['enabled','migrate','prune','invalidate','policyFingerprint','lineSignature','signature','remember','reusable'] as $method)
    check((new \ReflectionMethod(DecisionMemory::class,$method))->isPublic(),'public interface '.$method);
echo "PASS: {$checks} pure decision memory checks; no SQL/provider/filesystem mutations\n";
