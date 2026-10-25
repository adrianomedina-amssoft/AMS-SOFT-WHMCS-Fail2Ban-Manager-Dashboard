<?php
// CLI root repair of a private audited manifest, quota-aware, no IP ban operations.
if(PHP_SAPI!=='cli'||posix_geteuid()!==0)exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{Database,Policy,Privileged};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();$db=C::connection();
$path=realpath($argv[1]??'');if(!$path||!str_starts_with($path,'/var/backups/amssoft_fail2ban/')||fileowner($path)!==0||(fileperms($path)&0077))throw new RuntimeException('Private root manifest required');
$manifest=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);
if(time()-(int)$manifest['created_at']>3600)throw new RuntimeException('Audit manifest expired; prepare again');
if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Cycle busy');
$policy=false;
try{
 $policy=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;if(!$policy)throw new RuntimeException('Policy busy');
 if((int)Database::getConfig('schema_version')!==25)throw new RuntimeException('Deploy schema25 first');
 foreach($manifest['entries'] as $entry){
  $jail=$entry['jail'];if(!in_array($jail,['amsfb-apache-env-probe','amsfb-apache-git-probe','amsfb-apache-cms-probe'],true))throw new RuntimeException('Manifest target refused');
  if($entry['status']!=='ready'){Database::setConfig('native_repair_pending_'.$jail,$entry['reason']);echo json_encode(['jail'=>$jail,'applied'=>false,'code'=>$entry['reason']]),PHP_EOL;continue;}
  $usage=C::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('timestamp','>=',date('Y-m-d').' 00:00:00')->count();
  $last=C::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('jail',$jail)->max('timestamp');
  $reason=null;if($usage>=Policy::number('ai_filter_max_updates_per_day'))$reason='update_daily_limit';
  elseif($last&&strtotime($last)+Policy::number('ai_filter_update_cooldown_minutes')*60>time())$reason='update_cooldown';
  elseif(count($entry['patterns'])>Policy::number('ai_filter_max_regex'))$reason='regex_limit';
  if($reason){echo json_encode(['jail'=>$jail,'applied'=>false,'code'=>$reason]),PHP_EOL;Database::setConfig('native_repair_pending_'.$jail,$reason);continue;}
  $tmp=tempnam('/tmp','amsfb_rule_');
  try{
   file_put_contents($tmp,json_encode(['jail'=>$jail,'filter'=>$jail,'sha256'=>$entry['sha256'],'patterns'=>$entry['patterns'],'sources'=>$entry['sources'],'evidence'=>$entry['evidence']]));
   $r=Privileged::run(['extend-managed-rule',$tmp]);
  }finally{unlink($tmp);}
  if(empty($r['success'])){Database::setConfig('native_repair_pending_'.$jail,$r['code']??'repair_refused');echo json_encode(['jail'=>$jail,'applied'=>false,'code'=>$r['code']??'repair_refused']),PHP_EOL;continue;}
  Database::logEvent('',$jail,'native_rule_extended','Reparo auditado v2.2.14: origem/formato/positivos e tickets preservados.');
  Database::setConfig('native_repair_pending_'.$jail,'');
  echo json_encode(['jail'=>$jail,'applied'=>true,'sources'=>$r['sources']??[],'tickets_checked'=>$r['tickets_checked']??null]),PHP_EOL;
 }
}finally{if($policy)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
