<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
// Integration with the real adapter inside a rolled-back transaction only.
// No bootstrap hooks, outbound calls, migrations or fail2ban actions.
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4) . '/configuration.php';
require dirname(__DIR__,4) . '/vendor/autoload.php';
require dirname(__DIR__) . '/lib/Router.php';
$capsule = new WHMCS\Database\Capsule();
$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,
    'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
$db = $capsule->getConnection();
if ((int)AMS\Fail2Ban\Database::getConfig('schema_version') < 27 || (int)AMS\Fail2Ban\Database::getConfig('schema_version') > AMS\Fail2Ban\Migrations::VERSION) {
    throw new RuntimeException('Apply migrations explicitly before this test');
}
$ip = inet_ntop(inet_pton('2001:db8:ffff::' . bin2hex(random_bytes(2))));
$before = $db->table('mod_amssoft_fail2ban_ai_suggestions')->count();
$checks = 1;
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new RuntimeException('Production cycle still active; rerun after it completes');
$db->beginTransaction();
try {
    $db->enableQueryLog();
    AMS\Fail2Ban\Migrations::run();
    foreach($db->getQueryLog() as $query) {
        if(preg_match('/^\s*(ALTER|CREATE|DROP)/i',$query['query'])) throw new RuntimeException('Repeated migration performed DDL');
    }
    $db->disableQueryLog();
    $stamp=date('d/M/Y:H:i:s O');
    $line = $ip . ' - - ['.$stamp.'] "GET /.env HTTP/1.1" 404 100 "-" "fixture 🛡️"';
    $s=['ip'=>$ip,'severity'=>'high','confidence'=>95,'evidence'=>[$line],'source_log'=>'/var/log/apache2/access_whmcs.log','status'=>'pending','threat'=>'transactional test 🛡️'];
    $configKey=$db->table('mod_amssoft_fail2ban_config')->where('key','_enc_key')->value('value');
    AMS\Fail2Ban\Database::setConfig('ai_auto_enabled','0');
    $policy=AMS\Fail2Ban\Policy::values();$policy['ai_auto_enabled']='0';
    AMS\Fail2Ban\Policy::save($policy,0,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));
    foreach($policy as $key=>$value) {
        if(AMS\Fail2Ban\Database::getConfig($key)!==$value)throw new RuntimeException('Policy persistence mismatch: '.$key);$checks++;
    }
    AMS\Fail2Ban\Policy::save(['monitor_hours'=>'36'],0,\AMS\Fail2Ban\Database::getConfig('policy_version','0'));
    if(AMS\Fail2Ban\Database::getConfig('ai_mode')!==$policy['ai_mode'])throw new RuntimeException('Omitted policy field changed');$checks++;
    if($db->table('mod_amssoft_fail2ban_config')->where('key','_enc_key')->value('value')!==$configKey)throw new RuntimeException('Secret key changed');$checks++;
    $s['action']='ban';$s['_evidence_validated']=true;$s['_native_validated']=true;
    $s['failregex']='^<HOST> - \\S+ \\[\\s*\\] "GET /\\.env HTTP/1\\.[01]" (?:403|404) \\S+';
    $id = AMS\Fail2Ban\Database::saveSuggestion($s);
    if(AMS\Fail2Ban\Database::saveSuggestion($s)!==$id)throw new RuntimeException('Pending upsert mismatch');$checks++;
    AMS\Fail2Ban\Database::recordDetections($id,$s);
    AMS\Fail2Ban\Database::recordDetections($id,$s);
    if(AMS\Fail2Ban\Database::countRecentDetections($ip,10,null,$s['source_log'])!==1)throw new RuntimeException('Duplicate detection counted');$checks++;
    $s['evidence']=[str_replace($stamp,date('d/M/Y:H:i:s O',time()+1),$line)];
    AMS\Fail2Ban\Database::recordDetections($id,$s);
    if(AMS\Fail2Ban\Database::countRecentDetections($ip,10,null,$s['source_log'])!==2)throw new RuntimeException('Independent detection not counted');$checks++;
    $e=$db->table('mod_amssoft_fail2ban_detections')->where('suggestion_id',$id)->where('evidence',$line)->first();
    if($e->evidence!==$line||$e->source_log!==$s['source_log'])throw new RuntimeException('Evidence/source not preserved');$checks++;
    $db->table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$id)->update(['status'=>'rejected']);
    if(AMS\Fail2Ban\Database::countRecentDetections($ip,10,null,$s['source_log'])!==0)throw new RuntimeException('Rejected suggestion counts');$checks++;
} finally {
    $db->rollBack();
    $db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");
}
if($db->table('mod_amssoft_fail2ban_ai_suggestions')->where('ip',$ip)->exists()
    || $db->table('mod_amssoft_fail2ban_detections')->where('ip',$ip)->exists())throw new RuntimeException('Fixture not rolled back');
$checks++;
echo "PASS: {$checks} database checks; fixtures rolled back\n";
