<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/lib/LogCursor.php';
use AMS\Fail2Ban\LogCursor;
$n=0;$files=[];$dir=sys_get_temp_dir().'/amsfb-cursor-'.bin2hex(random_bytes(8));mkdir($dir,0700);
function lcCheck($v,$m){global $n;if(!$v)throw new RuntimeException($m);$n++;}
function lcFile($name,$data=''){global $dir,$files;$p=$dir.'/'.$name;file_put_contents($p,$data);$files[]=$p;return $p;}
function lcRead($path,$cursor,$limit=200){$r=LogCursor::read($path,$cursor,$limit);lcCheck($r['lines']<=$limit&&$r['bytes']<=262144,'Shared input bounds');return $r;}
function lcLegacy($path,$offset){$s=stat($path);$raw=file_get_contents($path);return ['file'=>$s['dev'].':'.$s['ino'],'generation'=>str_repeat('a',16),'offset'=>$offset,'anchor'=>$offset?hash('sha256',substr($raw,max(0,$offset-128),min(128,$offset))):'','draining'=>false];}
function lcNames($r){return array_column($r['records'],'line');}
try{
 $p=lcFile('basic.log',"first\n");$r=lcRead($p,null);lcCheck($r['mode']==='initialized_at_eof'&&!$r['records'],'Initial EOF');
 file_put_contents($p,"second\n",FILE_APPEND);$a=lcRead($p,$r['cursor']);lcCheck(lcNames($a)===['second'],'New line');
 lcCheck(!lcRead($p,$a['cursor'])['records'],'Stable reread');
 $c=lcLegacy($p,6);rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,'');
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['second'],'Legacy cursor drains old tail even if live empty');
 lcCheck($r['records'][0]['generation']===$c['generation']&&$r['records'][0]['offset']===6&&$r['records'][0]['file']===$c['file'],'Original source identity');
 lcCheck(!$r['more']&&count($r['cursor']['previous'])===1,'EOF old generation retained');
 lcCheck(!lcRead($p,$r['cursor'])['records'],'Rename reread once');
 file_put_contents($p.'.1',"late\n",FILE_APPEND);file_put_contents($p,"live\n");
 $r=lcRead($p,$r['cursor']);lcCheck(lcNames($r)===['late','live'],'Late writer and current source');
 lcCheck($r['records'][0]['file']!==$r['records'][1]['file'],'Separate inode identities');
 rename($p.'.1',$p.'.2');$files[]=$p.'.2';rename($p,$p.'.1');file_put_contents($p,"newest\n");
 file_put_contents($p.'.2',"older-late\n",FILE_APPEND);
 $r=lcRead($p,$r['cursor']);lcCheck(lcNames($r)===['older-late','newest'],'Multiple rotations and older late append');
 lcCheck(count($r['cursor']['previous'])===2,'Two watched generations');
 $p=lcFile('fair.log',"prefix\n");$c=lcRead($p,null)['cursor'];file_put_contents($p,str_repeat("old\n",1000),FILE_APPEND);
 rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,"current\n");
 $r=lcRead($p,$c,4);lcCheck(in_array('current',lcNames($r),true),'Old backlog cannot starve live source');lcCheck($r['more'],'Old backlog reports more despite live EOF');
 $total=count($r['records']);$cursor=$r['cursor'];for($i=0;$i<1100&&$r['more'];$i++){$r=lcRead($p,$cursor,4);$cursor=$r['cursor'];$total+=count($r['records']);}
 lcCheck($total===1001&&!$r['more'],'Multi-batch backlog drains exactly once');
 $p=lcFile('copy.log',"prefix stable\nconsumed\n");$c=lcRead($p,null)['cursor'];file_put_contents($p,"pending\n",FILE_APPEND);
 copy($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,"replacement\n");
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['pending','replacement'],'Verified copytruncate recovers tail');
 lcCheck($r['records'][0]['file']===$c['file']&&$r['records'][0]['generation']===$c['generation'],'Copy keeps logical identity');
 lcCheck($r['records'][1]['file']===$c['file']&&$r['records'][1]['generation']!==$c['generation'],'Same inode gets new generation');
 lcCheck(!lcRead($p,$r['cursor'])['records'],'Copied archive reread once');
 $retired=lcRead($p,$r['cursor']);unlink($p.'.1');$retired=lcRead($p,$retired['cursor']);
 lcCheck(in_array('archive_retired_after_eof',array_column($retired['diagnostics'],'code'),true),'Observed drained archive retirement is not a new loss');
 $p=lcFile('ambiguous.log',"stable-prefix\n");$c=lcRead($p,null)['cursor'];file_put_contents($p,"pending\n",FILE_APPEND);
 copy($p,$p.'.1');copy($p,$p.'.2');$files[]=$p.'.1';$files[]=$p.'.2';file_put_contents($p,"new\n");
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['new'],'Ambiguous copies never guessed');lcCheck(in_array('copy_unverified',array_column($r['diagnostics'],'code'),true),'Ambiguous diagnostic');
 $p=lcFile('missing.log',"seen\n");$c=lcRead($p,null)['cursor'];rename($p,$p.'.gone');$files[]=$p.'.gone';file_put_contents($p,"fresh\n");
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['fresh'],'Missing old source does not block live');lcCheck(in_array('archive_unavailable',array_column($r['diagnostics'],'code'),true),'Missing diagnostic');
 $r2=lcRead($p,$r['cursor']);lcCheck(!$r2['diagnostics'],'Missing diagnostic emitted once');
 rename($p.'.gone',$p.'.1');$files[]=$p.'.1';file_put_contents($p.'.1',"reappeared\n",FILE_APPEND);
 $r=lcRead($p,$r2['cursor']);lcCheck(lcNames($r)===['reappeared'],'Unavailable old inode can reappear');
 $p=lcFile('symlink.log',"seen\n");$c=lcRead($p,null)['cursor'];rename($p,$p.'.gone');$files[]=$p.'.gone';symlink($p.'.gone',$p.'.1');$files[]=$p.'.1';file_put_contents($p,"safe\n");
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['safe']&&in_array('archive_unavailable',array_column($r['diagnostics'],'code'),true),'Archive symlink refused');
 $link=lcFile('not-a-file');unlink($link);symlink($p,$link);$thrown=false;try{LogCursor::read($link,null,200);}catch(RuntimeException $e){$thrown=true;}lcCheck($thrown,'Current symlink refused');
 $p=lcFile('partial.log');$c=lcRead($p,null)['cursor'];file_put_contents($p,'incomplete');$r=lcRead($p,$c);
 lcCheck(!$r['records']&&!$r['more']&&$r['cursor']['offset']===0,'Partial line neither consumed nor spun');
 rename($p,$p.'.1');$files[]=$p.'.1';file_put_contents($p,"now\n");$r=lcRead($p,$r['cursor']);
 file_put_contents($p.'.1',"-done\n",FILE_APPEND);$r=lcRead($p,$r['cursor']);lcCheck(lcNames($r)===['incomplete-done'],'Partial old line can complete later');
 $p=lcFile('oversize.log');$c=lcRead($p,null)['cursor'];file_put_contents($p,str_repeat('x',300000)."\nvalid\n");
 $r=lcRead($p,$c);lcCheck($r['oversized']>0&&$r['cursor']['draining']&&$r['more'],'Oversized input bounded and resumable');
 $r=lcRead($p,$r['cursor']);lcCheck(lcNames($r)===['valid']&&!$r['cursor']['draining'],'Oversized recovery preserves next line');
 $p=lcFile('rewrite.log',"old\n");$c=lcRead($p,null)['cursor'];file_put_contents($p,"replacement longer than old\n");$r=lcRead($p,$c);
 lcCheck(lcNames($r)===['replacement longer than old'],'Regrowth above old offset still detected');lcCheck(in_array('copy_unverified',array_column($r['diagnostics'],'code'),true),'Unrecoverable rewrite explicit');
 $bad=$r['cursor'];$bad['previous']=array_fill(0,17,$c);$thrown=false;try{LogCursor::read($p,$bad,200);}catch(RuntimeException $e){$thrown=true;}lcCheck($thrown,'Generation metadata bound');
 $bad=$r['cursor'];$bad['offset']=-1;$thrown=false;try{LogCursor::read($p,$bad,200);}catch(RuntimeException $e){$thrown=true;}lcCheck($thrown,'Malformed cursor cannot rewind');
 $p=lcFile('unsafe.log',"seen\n");$c=lcRead($p,null)['cursor'];rename($p,$p.'.1');$files[]=$p.'.1';chmod($p.'.1',0666);file_put_contents($p,"current\n");
 $r=lcRead($p,$c);lcCheck(lcNames($r)===['current']&&in_array('archive_unavailable',array_column($r['diagnostics'],'code'),true),'World-writable archive refused');
 $fifo=$dir.'/fifo';$files[]=$fifo;posix_mkfifo($fifo,0600);$thrown=false;try{LogCursor::read($fifo,null,200);}catch(RuntimeException $e){$thrown=true;}lcCheck($thrown,'FIFO rejected without blocking');unlink($fifo);
 echo "PASS: {$n} isolated log cursor checks; private files only, no SQL/provider/daemon\n";
}finally{foreach(array_unique($files) as $file)if(file_exists($file)||is_link($file))unlink($file);rmdir($dir);}
