<?php
namespace AMS\Fail2Ban {
// Collector whitelist defaults are deterministic; no root bridge is called by fixtures.
class JailConfig {public function __construct(...$args){}public function readJailLocal(){return ['DEFAULT'=>['ignoreip'=>'']];}}
}
namespace {
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;
use AMS\Fail2Ban\{BehaviorStore,Database,LogCursor,RecentActivity};
$prefix='amsfb_rotation_fixture_'.bin2hex(random_bytes(6)).'_';
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4','prefix'=>$prefix]);$c->setEventDispatcher(new \Illuminate\Events\Dispatcher(new \Illuminate\Container\Container));$c->setAsGlobal();$c->bootEloquent();
date_default_timezone_set('America/Sao_Paulo');$db=C::connection();$n=0;$tables=[];$files=[];
$dir=sys_get_temp_dir().'/amsfb-rotation-sql-'.bin2hex(random_bytes(8));mkdir($dir,0700);
function rdCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function rdLine($target,$ip='198.18.97.10',$time=null){return $ip.' - - ['.date('d/M/Y:H:i:s O',$time??time()).'] "GET '.$target.' HTTP/1.1" 404 10 "-" "isolated-fixture"';}
function rdPath($name){global $dir,$files;$p=$dir.'/'.$name.'.log';file_put_contents($p,'');$files[]=$p;return $p;}
function rdKey($path){return 'adaptive_cursor.'.md5($path);}
function rdEvents($path){return (int)C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$path)->sum('events');}
try{
 // Unique connection-local names: no operational table can be written even if DDL fails.
 foreach(['mod_amssoft_fail2ban_config','mod_amssoft_fail2ban_rollups','mod_amssoft_fail2ban_logs'] as $name){
  $db->statement('CREATE TEMPORARY TABLE `'.$prefix.$name.'` LIKE `'.$name.'`');$tables[]=$name;
 }
 foreach(['schema_version'=>'34','ai_behavior_enabled'=>'0','ai_retired_paths'=>'','ai_application_probe_enabled'=>'0','ai_php_scan_enabled'=>'0','ai_whitelist_ips'=>'','ai_rollup_retention_hours'=>'72'] as $k=>$v)Database::setConfig($k,$v);
 $writes=0;$failKey=null;
 $db->listen(function($event)use($prefix,&$writes,&$failKey){
  if(!preg_match('/^\s*(?:insert|update|delete|replace)\b/i',$event->sql))return;
  if(!str_contains($event->sql,$prefix))throw new RuntimeException('Unprefixed DML refused');
  $writes++;
  if($failKey!==null&&preg_match('/^\s*update\b/i',$event->sql)&&in_array($failKey,$event->bindings,true)){
   $failKey=null;throw new RuntimeException('Injected cursor-write failure');
  }
 });
 $p=rdPath('rename');file_put_contents($p,rdLine('/seen')."\n");rdCheck(BehaviorStore::collect($p)['mode']==='initialized_at_eof','Initial EOF');
 $before=json_decode(Database::getConfig(rdKey($p)),true);$offset=$before['offset'];$pending=rdLine('/pending');file_put_contents($p,$pending."\n",FILE_APPEND);
 rename($p,$p.'.1');$files[]=$p.'.1';$live=rdLine('/live');file_put_contents($p,$live."\n");
 $r=BehaviorStore::collect($p);rdCheck($r['events']===2&&rdEvents($p)===2,'Both generations stored');
 $samples=[];foreach(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$p)->get() as $row)$samples=array_merge($samples,json_decode($row->samples,true));
 $old=array_values(array_filter($samples,fn($e)=>$e['line']===$pending))[0];
 rdCheck($old['id']===hash('sha256',$p."\0".$before['file']."\0".$before['generation']."\0".$offset),'Original offset and generation in ID');
 rdCheck(BehaviorStore::collect($p)['events']===0&&rdEvents($p)===2,'No duplicate count on repeat');
 file_put_contents($p.'.1',rdLine('/late')."\n",FILE_APPEND);rdCheck(BehaviorStore::collect($p)['events']===1&&rdEvents($p)===3,'Late append stored');
 $row=C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$p)->where('pattern',BehaviorStore::pattern($pending))->first();
 C::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->update(['processing_state'=>'review','validation_attempts'=>3]);
 file_put_contents($p.'.1',$pending."\n",FILE_APPEND);BehaviorStore::collect($p);
 $row=C::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->first();rdCheck($row->processing_state==='review'&&(int)$row->validation_attempts===3,'Pending review budget preserved');
 $p=rdPath('rollback');BehaviorStore::collect($p);$key=rdKey($p);$before=Database::getConfig($key);
 file_put_contents($p,rdLine('/rollback-old')."\n");rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,rdLine('/rollback-live')."\n");
 $failKey=$key;$thrown=false;try{BehaviorStore::collect($p);}catch(RuntimeException $e){$thrown=$e->getMessage()==='Injected cursor-write failure';}
 rdCheck($thrown,'Cursor failure injected');rdCheck(Database::getConfig($key)===$before&&rdEvents($p)===0,'Rows and cursor rolled back together');
 $r=BehaviorStore::collect($p);rdCheck($r['events']===2&&rdEvents($p)===2,'Retry collects once after rollback');
 rdCheck(BehaviorStore::collect($p)['events']===0&&rdEvents($p)===2,'Retry remains idempotent');
 $p=rdPath('bounded');BehaviorStore::collect($p);file_put_contents($p,str_repeat(rdLine('/bulk')."\n",700));rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,rdLine('/current')."\n");
 Database::setConfig('ai_log_lines','200');$r=BehaviorStore::collect($p);rdCheck($r['more']&&$r['events']<=200,'Old backlog reports continuation');
 rdCheck(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$p)->where('pattern',BehaviorStore::pattern(rdLine('/current')))->exists(),'Live source progresses');
 $loops=1;while($r['more']&&$loops++<20)$r=BehaviorStore::collect($p);
 rdCheck(!$r['more']&&rdEvents($p)===701,'Bounded batches drain full tail');
 $p=rdPath('copy');file_put_contents($p,rdLine('/consumed')."\n");BehaviorStore::collect($p);file_put_contents($p,rdLine('/copy-tail')."\n",FILE_APPEND);copy($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,rdLine('/copy-new')."\n");
 rdCheck(BehaviorStore::collect($p)['events']===2&&rdEvents($p)===2,'Copytruncate verified in real SQL flow');
 $p=rdPath('expired');BehaviorStore::collect($p);$cold=rdLine('/cold','198.18.97.11',time()-3600);file_put_contents($p,$cold."\n");rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,'');
 rdCheck(BehaviorStore::collect($p)['events']===1,'Retained cold source stored with original time');
 $coldrow=(array)C::table('mod_amssoft_fail2ban_rollups')->where('source_log',$p)->first();rdCheck(RecentActivity::latest($coldrow)<RecentActivity::cutoff(),'Cold recovery does not become recent paid evidence');
 $p=rdPath('whitelist');BehaviorStore::collect($p);Database::setConfig('ai_whitelist_ips','198.18.97.12');file_put_contents($p,rdLine('/ignored','198.18.97.12')."\n");
 rdCheck(BehaviorStore::collect($p)['events']===0&&rdEvents($p)===0,'Whitelist preserved');
 $gapCount=C::table('mod_amssoft_fail2ban_logs')->where('action','log_rotation')->count();rdCheck($gapCount>=4,'Rotation diagnostics stored in isolated log table');
 echo "PASS: {$n} isolated SQL rotation checks; {$writes} prefixed DML statements on connection-local temporary tables; no operational writes/provider/native calls\n";
}finally{
 while($db->transactionLevel()>0)$db->rollBack();
 foreach($tables as $name)$db->statement('DROP TEMPORARY TABLE IF EXISTS `'.$prefix.$name.'`');
 foreach(array_unique($files) as $file)if(is_file($file))unlink($file);rmdir($dir);
}
}
