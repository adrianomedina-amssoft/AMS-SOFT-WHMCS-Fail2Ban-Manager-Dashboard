<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Database,Maintenance,Fail2BanClient};
use WHMCS\Database\Capsule;
$capsule=new Capsule();$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,
    'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
$checks=0;function check($v,$label){global $checks;if(!$v)throw new RuntimeException($label);$checks++;}
$db=Capsule::connection();
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)
    throw new RuntimeException('Production cycle still active; rerun after it completes');
$db->beginTransaction();$jobId='';
try {
    $client=new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client');
    $old=$db->table('mod_amssoft_fail2ban_logs')->insertGetId(['ip'=>'198.51.100.246','jail'=>'fixture','action'=>'ban','reason'=>'old fixture','timestamp'=>date('Y-m-d H:i:s',time()-10)]);
    $preview=Maintenance::preview(['kind'=>'archive','scope'=>'ai','monitor'=>'0'],1,$client);$jobId=$preview['nonce'];
    $row=$db->table('mod_amssoft_fail2ban_jobs')->where('id',$jobId)->first();$p=json_decode($row->payload,true);
    check(in_array($old,$p['record_ids']['logs']),'Preview freezes old IDs');
    // Narrow fixture-only archival; no live bans are in this archive-only job.
    foreach($p['record_ids'] as $table=>&$ids)$ids=$table==='logs'?[$old]:[];unset($ids);
    $p['rollup_revisions']=[];
    $db->table('mod_amssoft_fail2ban_jobs')->where('id',$jobId)->update(['payload'=>json_encode($p)]);
    $new=$db->table('mod_amssoft_fail2ban_logs')->insertGetId(['ip'=>'198.51.100.247','jail'=>'fixture','action'=>'ban','reason'=>'new fixture','timestamp'=>$p['cutoff']]);
    try{Maintenance::queue(['nonce'=>$jobId,'confirmation'=>'wrong'],1);throw new RuntimeException('Wrong phrase accepted');}catch(InvalidArgumentException $expected){$checks++;}
    try{Maintenance::queue(['nonce'=>$jobId,'confirmation'=>'EXECUTAR MANUTENCAO'],2);throw new RuntimeException('Other actor accepted');}catch(InvalidArgumentException $expected){$checks++;}
    $queued=Maintenance::queue(['nonce'=>$jobId,'confirmation'=>'EXECUTAR MANUTENCAO'],1);
    check($queued['status']==='queued','Queue is separate from save');
    check(Maintenance::queue(['nonce'=>$jobId,'confirmation'=>'EXECUTAR MANUTENCAO'],1)['repeated'],'Repeated request idempotent');
    // Avoid touching any unrelated preexisting jobs during the worker fixture.
    $db->table('mod_amssoft_fail2ban_jobs')->where('id','!=',$jobId)->whereIn('status',['queued','running','monitoring'])->update(['status'=>'fixture_hidden']);
    Maintenance::tick($client);
    $job=$db->table('mod_amssoft_fail2ban_jobs')->where('id',$jobId)->first();$result=json_decode($job->result,true);
    check($job->status==='completed','Archive-only worker finishes');
    check($result['backup_complete']&&count($result['archives'])===2,'Verified private manifest and data before deletion');
    check(!$db->table('mod_amssoft_fail2ban_logs')->where('id',$old)->exists(),'Old target removed in transaction');
    check($db->table('mod_amssoft_fail2ban_logs')->where('id',$new)->exists(),'New record in same second preserved by frozen IDs');
    check($db->table('mod_amssoft_fail2ban_logs')->where('action','maintenance_queued')->exists(),'Audit is preserved');
    Maintenance::tick($client);
    check($db->table('mod_amssoft_fail2ban_logs')->where('id',$new)->exists(),'Repeat tick never broadens scope');
} finally {$db->rollBack();$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
echo "PASS: {$checks} maintenance database checks; SQL rolled back; private fixture archive job-{$jobId} retained\n";
