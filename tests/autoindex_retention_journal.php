<?php
if(PHP_SAPI!=='cli')exit(1);require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{AutoindexRetention as R,AutoindexReview as A,AutoindexJournal as J};
date_default_timezone_set('America/Sao_Paulo');$n=0;$now=strtotime('2026-10-16 12:00:00');$ip='198.18.82.1';$at=$now-60;
$dir=sys_get_temp_dir().'/amsfb-retention-'.bin2hex(random_bytes(8));mkdir($dir,0700);
function retCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function retLine($ip,$t,$error=false){return $error?'['.date('D M d H:i:s',$t).'.000000 '.date('Y',$t).'] [autoindex:error] [pid 1] [client '.$ip.':54321] AH01276: Cannot serve directory /var/www/html/: No matching DirectoryIndex (index.php) found, and server-generated directory index forbidden by Options directive':$ip.' - - ['.date('d/M/Y:H:i:s O',$t).'] "GET / HTTP/1.1" 403 10 "-" "fixture"';}
function retFixtures($dir){global $now,$at,$ip;foreach(R::BASES as $base)for($day=0;$day<3;$day++){
 $suffix=$day===0?'':($day===1?'.1':'.2.gz');$t=$day===0?$at:strtotime('2026-10-'.(16-$day).' 12:00:00');
 $line=retLine($day===0?$ip:'198.18.82.2',$t,str_starts_with($base,'error'));if($base==='other_vhosts_access.log')$line='fixture.invalid:80 '.$line;
 $f=gzopen($dir.'/'.$base.$suffix,'wb');gzwrite($f,$line."\n");gzclose($f);
}}
try{
 foreach(['preview','apply','resume'] as $mode)retCheck(J::mode([$mode=>false,'backup'=>'fixture','job'=>str_repeat('a',32)])===$mode,'CLI mode not selected '.$mode);
 try{J::mode(['apply'=>false,'resume'=>false,'backup'=>'fixture','job'=>str_repeat('a',32)]);retCheck(false,'Ambiguous modes accepted');}catch(InvalidArgumentException $e){retCheck(true,'CLI ambiguity refused');}
 retFixtures($dir);$scan=R::scan($dir,[$ip],3,24,$now);retCheck($scan['retention']['status']==='known','Valid rotation chain refused');retCheck(R::unchanged($scan['retention'],$now),'Stable files refused');
 $t=['jail'=>'apache-autoindex-dir','ip'=>$ip,'ticket'=>date('Y-m-d H:i:s',$at).' + 604800 = '.date('Y-m-d H:i:s',$at+604800)];
 retCheck(A::assess($t,[$t],$scan['events'][$ip],[],$scan['retention'],$now)['eligible'],'Valid paired proof refused');
 foreach(R::BASES as $base){file_put_contents($dir.'/'.$base.'.1','');$bad=R::scan($dir,[$ip],3,24,$now);retCheck($bad['retention']['status']==='unknown','Empty day accepted '.$base);retCheck(!A::assess($t,[$t],$bad['events'][$ip]??[],[],$bad['retention'],$now)['eligible'],'Empty day released');retFixtures($dir);}
 file_put_contents($dir.'/access.log.1',retLine($ip,strtotime('2026-10-13 12:00:00'))."\n");retCheck(R::scan($dir,[$ip],3,24,$now)['retention']['status']==='unknown','Wrong day accepted');retFixtures($dir);
 rename($dir.'/access.log.1',$dir.'/missing-fixture');retCheck(R::scan($dir,[$ip],3,24,$now)['retention']['status']==='unknown','Missing source accepted');rename($dir.'/missing-fixture',$dir.'/access.log.1');
 file_put_contents($dir.'/access.log',retLine($ip,$at));retCheck(R::scan($dir,[$ip],3,24,$now)['retention']['status']==='unknown','Partial line accepted');retFixtures($dir);
 $valid=R::scan($dir,[$ip],3,24,$now);file_put_contents($dir.'/access.log',"changed\n",FILE_APPEND);retCheck(!R::unchanged($valid['retention'],$now),'Append after scan accepted');retFixtures($dir);
 retCheck(!R::unchanged(R::scan($dir,[$ip],3,24,$now)['retention'],$now+61),'Expired retention accepted');
 // Journal failure between native removal and result commit, followed by safe resume.
 $job=$dir.'/job';$t2=['jail'=>'apache-autoindex-ah01276','ip'=>$ip,'ticket'=>$t['ticket']];J::create($job,['job'=>'fixture','approved'=>[$t,$t2],'results'=>[]]);$live=[$t,$t2];$calls=0;$audit=[];$throw=true;
 $read=static function()use(&$live){return $live;};$assess=fn()=>['eligible'=>true,'reason'=>'fixture-proof'];$stable=fn()=>true;
 $remove=static function($target)use(&$live,&$calls,&$throw){$calls++;$live=array_values(array_filter($live,fn($x)=>$x!==$target));if($throw){$throw=false;throw new RuntimeException('Injected interruption after native effect');}return ['success'=>true];};
 $log=static function($target,$i,$status)use(&$audit){$audit[$i]=$status;};
 $first=J::run($job,$read,$assess,$stable,$remove,$log,$now);retCheck(!$first['complete']&&$calls===1,'Injected interruption not retained');
 $second=J::run($job,$read,$assess,$stable,$remove,$log,$now);retCheck($second['complete']&&$calls===2&&count($audit)===2,'Resume repeated native removal or missed audit');
 J::run($job,$read,$assess,$stable,$remove,$log,$now);retCheck($calls===2,'Completed job repeated mutation');
 $job2=$dir.'/renewed';J::create($job2,['approved'=>[$t],'results'=>[]]);$renewed=$t;$renewed['ticket'].=' renewed';$live=[$renewed];$before=$calls;$x=J::run($job2,$read,$assess,$stable,$remove,$log,$now);retCheck($calls===$before&&$x['results'][0]['status']==='renewed','Renewed ticket removed');
 $job3=$dir.'/changed';J::create($job3,['approved'=>[$t],'results'=>[]]);$live=[$t];$x=J::run($job3,$read,$assess,fn()=>false,$remove,$log,$now);retCheck(!$x['complete']&&$calls===$before,'Changed logs allowed mutation');
 $x=J::run($job3,$read,fn()=>['eligible'=>false,'reason'=>'retention_unverified'],$stable,$remove,$log,$now);retCheck(!$x['complete']&&$calls===$before,'Unknown retention authorized mutation');
 $job4=$dir.'/audit-failure';J::create($job4,['approved'=>[$t],'results'=>[]]);$live=[$t];$x=J::run($job4,$read,$assess,$stable,$remove,fn()=>throw new RuntimeException('audit unavailable'),$now);$savedCalls=$calls;
 retCheck(!$x['complete']&&is_file($job4.'/ticket-0000-result.json'),'Native result lost after audit failure');J::run($job4,$read,$assess,$stable,$remove,$log,$now);retCheck($calls===$savedCalls,'Audit resume repeated unban');
 $hash=hash_file('sha256',$job.'/manifest.json');try{J::create($job,['approved'=>[$t],'results'=>[]]);retCheck(false,'Manifest overwritten');}catch(RuntimeException $e){retCheck(hash_file('sha256',$job.'/manifest.json')===$hash,'Immutable manifest damaged');}
}finally{
 // Exact private fixture directory only; no production file or native operation is involved.
 $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as $p){if($p->isDir())rmdir($p->getPathname());else unlink($p->getPathname());}rmdir($dir);
}
echo "PASS: {$n} retention/journal checks; private fixtures and simulated native effects only\n";
