<?php
namespace AMS\Fail2Ban {
class TailFixture {static string $file;static bool $after=false,$unreadable=false;static string $fault='';static int $bytes=0;}
function realpath($p){if($p==='/var/log/escape.log')return '/etc/passwd';if(in_array($p,['/var/log/fixture.log','/var/log/alias.log'],true))return TailFixture::$after&&TailFixture::$fault==='path'?'/var/log/changed.log':'/var/log/fixture.log';return \realpath($p);}
function is_file($p){return $p==='/var/log/fixture.log'||\is_file($p);}
function is_readable($p){return $p==='/var/log/fixture.log'?!TailFixture::$unreadable:\is_readable($p);}
function filesize($p){return \filesize($p==='/var/log/fixture.log'?TailFixture::$file:$p);}
function stat($p){$r=\stat($p==='/var/log/fixture.log'?TailFixture::$file:$p);if(TailFixture::$after&&TailFixture::$fault==='rotate')$r['ino']++;return $r;}
function fopen($p,$mode){return \fopen($p==='/var/log/fixture.log'?TailFixture::$file:$p,$mode);}
function fstat($fp){$r=\fstat($fp);if(TailFixture::$after&&TailFixture::$fault==='truncate')$r['size']=0;return $r;}
function stream_get_contents($fp,$length){$s=\stream_get_contents($fp,$length);TailFixture::$bytes+=strlen($s);TailFixture::$after=true;return $s;}
}
namespace {
require dirname(__DIR__).'/lib/Router.php';use AMS\Fail2Ban\{LogTail as T,TailFixture as F,LogView as V};
$n=0;function t47($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
$dir=sys_get_temp_dir().'/amsfb-tail47-'.bin2hex(random_bytes(8));mkdir($dir,0700);F::$file=$dir.'/fixture.log';
function content47($s){file_put_contents(F::$file,$s);clearstatcache();F::$after=false;F::$fault='';F::$bytes=0;F::$unreadable=false;}
try{
 content47('');$r=T::read('/var/log/fixture.log',100);t47($r['empty_file']&&$r['lines']===[]&&$r['bytes_read']===0,'Empty confirmed');
 foreach(["a\nb\n"=>['a','b'],"a\r\nb\r\n"=>['a','b'],"a\nb unfinished"=>['a'],"\n\n"=>['',''],"unfinished"=>[]] as $text=>$expected){content47($text);$r=T::read('/var/log/fixture.log',100);t47($r['lines']===$expected,'Physical complete lines');}
 content47("a\nb");t47((bool)T::read('/var/log/fixture.log',100)['warnings'],'Incomplete is explicit');
 content47(implode("\n",range(1,150))."\n");$r=T::read('/var/log/fixture.log',100);t47(count($r['lines'])===100&&$r['lines'][0]==='51'&&end($r['lines'])==='150','Last N exact');
 content47(str_repeat("prefix ".str_repeat('x',90)."\n",200000)."last\n");$r=T::read('/var/log/fixture.log',100);t47($r['bounded']&&F::$bytes===T::BYTES+1&&end($r['lines'])==='last','Large file bounded read');t47(count($r['lines'])===100&&str_starts_with($r['lines'][0],'prefix '),'No leading fragment');
 content47(str_repeat('x',T::LINE_BYTES+1)."\nlast\n");$r=T::read('/var/log/fixture.log',100);t47($r['lines']===['last']&&count($r['warnings'])===1,'Oversized complete line omitted');
 content47(str_repeat('x',T::BYTES*2));$r=T::read('/var/log/fixture.log',100);t47(!$r['empty_file']&&$r['lines']===[]&&$r['warnings'],'Huge fragment not empty file');
 content47("bad\xff\ncontrol\0\x1b\n");$r=T::read('/var/log/fixture.log',100);t47(preg_match('//u',implode('',$r['lines']))===1&&str_contains($r['lines'][1],'\\x00\\x1B'),'UTF8 and control display');t47((bool)$r['warnings'],'Normalization disclosed');
 content47("ok\n");t47(T::read('/var/log/alias.log',10)['lines']===['ok'],'Internal alias');
 foreach(['/etc/passwd','/var/log/escape.log','/var/log/../etc/passwd',"/var/log/a\0.log",'/var/log/nonexistent-amsfb47.log'] as $p){F::$after=false;try{T::read($p,100);t47(false,'Unsafe accepted');}catch(InvalidArgumentException $e){t47(true,'Path refused');}}
 foreach(['rotate','truncate','path'] as $fault){content47("ok\n");F::$fault=$fault;try{T::read('/var/log/fixture.log',100);t47(false,'Race accepted');}catch(RuntimeException $e){t47(true,'Race refused');}}
 content47("ok\n");F::$unreadable=true;try{T::read('/var/log/fixture.log',100);t47(false,'Unreadable accepted');}catch(InvalidArgumentException $e){t47(true,'Permission explicit');}
 foreach([0,9,1001] as $limit){try{T::read('/var/log/fixture.log',$limit);t47(false,'Bad bound');}catch(InvalidArgumentException $e){t47(true,'Bound refused');}}
 foreach([[],['x'],false,100,'0','9','-1','1001','1e2'] as $lines){try{V::request(['path'=>'/var/log/fixture.log','lines'=>$lines]);t47(false,'Malformed lines');}catch(InvalidArgumentException $e){t47(true,'Types and range');}}
 foreach([[],true,'/etc/passwd',str_repeat('x',501),"/var/log/x\n.log"] as $path){try{V::request(['path'=>$path]);t47(false,'Malformed path');}catch(InvalidArgumentException $e){t47(true,'Path input');}}
 t47(V::request(['path'=>'/var/log/fixture.log','lines'=>'1000'])===['/var/log/fixture.log',1000],'Max request');
}finally{unlink(F::$file);rmdir($dir);}
echo "PASS: $n bounded log tail/path/rotation/UTF8 checks; private fixtures only\n";
}
