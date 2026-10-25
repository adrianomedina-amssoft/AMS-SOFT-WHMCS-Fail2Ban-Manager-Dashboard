<?php
/** Explicit opt-in; existing schema only, cycle/policy locks, all SQL rolled back.
 * Run: AMSFB_TEST_WHMCS_ROOT=/var/www/html/whmcs php tests/decision_memory_database.php
 * Uses local provider fixtures only. Never calls migrations or privileged helpers.
 */
if (PHP_SAPI!=='cli') exit(1);
$root=getenv('AMSFB_TEST_WHMCS_ROOT');
if (!$root || !is_file($root.'/configuration.php')) throw new RuntimeException('Set AMSFB_TEST_WHMCS_ROOT explicitly.');
require $root.'/configuration.php'; require $root.'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Database,DecisionMemory,BehaviorStore,Policy};
use WHMCS\Database\Capsule as C;
$capsule=new C();
$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
    'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();$db=C::connection();
$checks=0;
function check($ok,$label): void {global $checks;if(!$ok)throw new RuntimeException('FAIL: '.$label);$checks++;}
function ev(string $line,string $salt): array {
    return ['id'=>hash('sha256',$salt),'ip'=>explode(' ',$line,2)[0],
        'pattern'=>BehaviorStore::pattern($line),'line'=>$line,'time'=>BehaviorStore::eventTime($line)];
}
if ((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',5) AS acquired")->acquired!==1) throw new RuntimeException('Cycle busy');
$policyLock=false;$transaction=false;$source=null;
try {
    $policyLock=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;
    if (!$policyLock) throw new RuntimeException('Policy busy');
    if ((int)Database::getConfig('schema_version','0')<23) throw new RuntimeException('Schema23 required; this test never migrates.');
    foreach ([DecisionMemory::TABLE,'mod_amssoft_fail2ban_config','mod_amssoft_fail2ban_rollups',
        'mod_amssoft_fail2ban_ai_suggestions','mod_amssoft_fail2ban_detections','mod_amssoft_fail2ban_evidence_links'] as $table) {
        $status=$db->selectOne('SHOW TABLE STATUS WHERE Name = ?',[$table]);
        if (!$status || strcasecmp($status->Engine,'InnoDB')!==0) throw new RuntimeException('Transactional existing tables required: '.$table);
    }
    $db->beginTransaction();$transaction=true;
    Database::setConfig('schema_version','23'); // Legacy exact-memory repository contract.
    $globalWhitelist=Database::getConfig('ai_whitelist_ips','');
    foreach (['ai_reuse_enabled'=>1,'ai_reuse_min_confidence'=>95,'ai_reuse_minutes'=>30,
        'ai_reuse_activity_multiplier'=>2,'ai_reuse_sample_percent'=>1] as $key=>$value) Database::setConfig($key,(string)$value);
    $ip='198.18.39.246';$now=time();$bucket=(int)(floor($now/600)*600);
    $line=$ip.' - alice ['.date('d/M/Y:H:i:s O',$now).'] "GET /clientarea.php?a=1 HTTP/1.1" 200 100 "-" "fixture"';
    $second=str_replace('?a=1','?a=2',$line);
    // Pick a subject outside sampling for both classifications and TTLs used
    // below, including adjacent clock windows to avoid boundary flakiness.
    for ($attempt=0;$attempt<1000;$attempt++) {
        $source='/var/log/apache2/access-memory-fixture-'.bin2hex(random_bytes(12)).'.log';
        $unsampled=true;
        foreach (['monitor','whitelist'] as $action) {
            $key=hash('sha256',implode("\0",[$ip,$source,BehaviorStore::pattern($line),$action]));
            foreach ([30,240] as $minutes) foreach ([-1,0,1] as $offset) {
                $window=intdiv($now,$minutes*60)+$offset;
                $sample=hexdec(substr(hash('sha256',$key."\0".date('Y-m-d H:i:s',$bucket)."\0".$window),0,8))%100;
                if ($sample<10) $unsampled=false;
            }
        }
        if ($unsampled) break;
    }
    check($unsampled,'fixture outside deterministic sampling');
    $events=[ev($line,$source.'one'),ev($second,$source.'two')];
    $row=['id'=>hash('sha256',$source),'ip'=>$ip,'source_log'=>$source,'pattern'=>BehaviorStore::pattern($line),
        'bucket'=>date('Y-m-d H:i:s',$bucket),'events'=>2,'revision'=>1,'samples'=>json_encode($events),
        'behavior_complete'=>1,'behavior_variants'=>json_encode(array_map(fn($e)=>DecisionMemory::lineSignature($e['line'],$ip),$events))];
    C::table('mod_amssoft_fail2ban_rollups')->insert($row);
    // Older bucket represents one original variant. Baseline is the aggregate,
    // not the selected row's count. Only original row goes to remember().
    $older=$row;$older['id']=hash('sha256',$source.'older');$older['bucket']=date('Y-m-d H:i:s',$bucket-600);
    $older['events']=1;$older['samples']=json_encode([ev($line,$source.'older-event')]);
    $older['behavior_variants']=json_encode([DecisionMemory::lineSignature($line,$ip)]);
    C::table('mod_amssoft_fail2ban_rollups')->insert($older);
    $provider=static fn()=>['ip'=>$ip,'source_log'=>$source,'_pattern'=>$row['pattern'],
        '_task_id'=>$row['id'],'_analysis_key'=>hash('sha256',$source.'api'),
        '_events'=>$events,'evidence'=>[$line,$second],'action'=>'monitor','confidence'=>95,
        'severity'=>'low','threat'=>'Fixture observation','status'=>'pending'];
    $item=$provider();$id=Database::saveSuggestion($item);
    $partial=$item;$partial['_events']=[$events[0]];$partial['evidence']=[$line];
    DecisionMemory::remember($row,$partial,$id);
    check(C::table(DecisionMemory::TABLE)->where('source_log',$source)->count()===0,'stored two variants but API proved only one cannot seed');
    $partial=$item;$partial['evidence']=[$line];DecisionMemory::remember($row,$partial,$id);
    check(C::table(DecisionMemory::TABLE)->where('source_log',$source)->count()===0,'API proof without every cited variant cannot seed');
    DecisionMemory::remember($row,$item,$id);
    $memory=(array)C::table(DecisionMemory::TABLE)->where('source_log',$source)->first();
    check((int)$memory['baseline_events']===3,'original row seeds original aggregate24h baseline');
    check(DecisionMemory::reusable($row),'real repository hit');
    $before=(array)C::table(DecisionMemory::TABLE)->where('key',$memory['key'])->first();
    DecisionMemory::reusable($row);
    check((array)C::table(DecisionMemory::TABLE)->where('key',$memory['key'])->first()===$before,'hit never renews TTL or mutates metadata');
    $other=$row;$other['ip']='198.18.39.247';check(!DecisionMemory::reusable($other),'new IP never hits');
    foreach (['?a=2'=>'?a=3','fixture'=>'other-UA'] as $from=>$to) {
        $changed=$row;$changed['behavior_complete']=0;$changed['samples']=json_encode([$events[0],ev(str_replace($from,$to,$second),$source.$to)]);
        check(!DecisionMemory::reusable($changed),'query/UA change invalidates');
    }
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$id)->update(['status'=>'rejected']);
    check(!DecisionMemory::reusable($row),'revoked live decision invalidates');
    C::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$id)->update(['status'=>'pending','classification'=>'whitelist']);
    check(!DecisionMemory::reusable($row),'live classification changed invalidates');
    $item['action']='whitelist';Database::saveSuggestion($item);DecisionMemory::remember($row,$item,$id);
    check(!C::table(DecisionMemory::TABLE)->where('key',$memory['key'])->exists(),'fresh whitelist removes old monitor even with timestamp/ID tie');
    check(C::table(DecisionMemory::TABLE)->where('source_log',$source)->count()===1,'one classification memory survives direct remember');
    check(DecisionMemory::reusable($row),'whitelist decision supported without global allowlist');
    check(Database::getConfig('ai_whitelist_ips','')===$globalWhitelist,'no global whitelist mutation');
    Database::setConfig('ai_reuse_min_confidence','90');Database::setConfig('ai_reuse_minutes','240');Database::setConfig('ai_reuse_activity_multiplier','10');
    $item['confidence']=92;Database::saveSuggestion($item);DecisionMemory::remember($row,$item,$id);
    check(DecisionMemory::reusable($row),'approved UI bounds and whitelist92 supported');
    Database::setConfig('ai_reuse_activity_multiplier','2');DecisionMemory::remember($row,$item,$id);
    $activity=$older;$activity['id']=hash('sha256',$source.'activity');$activity['bucket']=date('Y-m-d H:i:s',$bucket-1200);
    $activity['events']=3;$activity['samples']=json_encode([ev($line,$source.'activity-event')]);
    C::table('mod_amssoft_fail2ban_rollups')->insert($activity);
    check(!DecisionMemory::reusable($row),'aggregate at2x baseline invalidates');
    C::table('mod_amssoft_fail2ban_rollups')->where('id',$activity['id'])->delete();
    Database::setConfig('ai_reuse_sample_percent','10');DecisionMemory::remember($row,$item,$id);
    $expected=DecisionMemory::reusable($row);
    for($revision=2;$revision<=12;$revision++) {
        C::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->update(['revision'=>$revision]);$row['revision']=(string)$revision;
        check(DecisionMemory::reusable($row)===$expected,'collect revision never rerolls sample');
    }
    Database::setConfig('ai_reuse_sample_percent','100');DecisionMemory::remember($row,$item,$id);
    check(!DecisionMemory::reusable($row),'100percent always forces API');
    Database::setConfig('ai_reuse_sample_percent','1');DecisionMemory::remember($row,$item,$id);
    check(DecisionMemory::reusable($row),'1percent unsampled fixture hit restored');
    // A locally fixture-validated peer changes real campaign membership. No
    // regex execution/provider call is implied by these repository fixtures.
    $peer=str_replace($ip,'198.18.39.245',$line);$attack=$item;
    $attack['ip']='198.18.39.245';$attack['action']='ban';$attack['confidence']=99;
    $attack['_analysis_key']=hash('sha256',$source.'peer-api');$attack['evidence']=[$peer];
    $attack['_events']=[ev($peer,$source.'peer-event')];$attack['_native_validated']=true;$attack['_evidence_validated']=true;
    $peerId=Database::saveSuggestion($attack);Database::recordDetections($peerId,$attack);
    check(!DecisionMemory::reusable($row),'validated campaign membership change invalidates');
    DecisionMemory::remember($row,$item,$id);check(DecisionMemory::reusable($row),'fresh API can remember changed campaign');
    Database::setConfig('ai_behavior_min_ips','3');check(!DecisionMemory::reusable($row),'unrelated policy change invalidates');
    DecisionMemory::remember($row,$item,$id);
    C::table(DecisionMemory::TABLE)->where('source_log',$source)->update(['valid_until'=>date('Y-m-d H:i:s',time()-1)]);
    check(!DecisionMemory::reusable($row),'strict expired TTL');
    $oldKey=hash('sha256',$source.'expired-metadata');$old=$memory;$old['key']=$oldKey;
    $old['valid_until']=date('Y-m-d H:i:s',time()-(Policy::number('ai_evidence_retention_days')+1)*86400);
    C::table(DecisionMemory::TABLE)->insert($old);
    $rollups=C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->count();
    DecisionMemory::prune();
    check(!C::table(DecisionMemory::TABLE)->where('key',$oldKey)->exists(),'prune expired metadata');
    check(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->count()===$rollups,'prune preserves original evidence');
    $foreign=$memory;$foreign['ip']='198.18.39.244';
    $foreign['key']=hash('sha256',implode("\0",[$foreign['ip'],$source,$row['pattern'],'monitor']));
    C::table(DecisionMemory::TABLE)->insert($foreign);
    DecisionMemory::invalidate($row);
    check(C::table(DecisionMemory::TABLE)->where('source_log',$source)->where('ip',$ip)->count()===0,'fresh API ban/low confidence can invalidate both normal memories');
    check(C::table(DecisionMemory::TABLE)->where('key',$foreign['key'])->exists(),'invalidation preserves other IP memory');
    check(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->count()===$rollups,'invalidation preserves original history');
} finally {
    if ($transaction) $db->rollBack();
    if ($policyLock) $db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");
    $db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");
}
if ($source!==null) check(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->count()===0,'fixture SQL rolled back');
echo "PASS: {$checks} actual repository decision memory checks; SQL rolled back, no DDL/provider/host writes\n";
