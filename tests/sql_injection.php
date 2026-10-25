<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($k,$d=''){return ['schema_version'=>'35','ai_non_offensive_paths'=>"/\n/index.php\n/cart.php\n/callback.php"][$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
if(in_array('--json',$argv,true)){$in=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);echo json_encode(['pattern'=>SqlInjection::queryPattern(),'lines'=>array_map(fn($l)=>['recognized'=>SqlInjection::fromLine($l),'non_offensive'=>RequestEvidence::nonOffensiveLine($l),'family'=>AttackFamily::fromLine($l)],$in['lines'])]);exit;}
$n=0;function sqlCheck($v,$why){global $n;if(!$v)throw new \RuntimeException($why);$n++;}
function sqlLine($t,$status=200,$ip='198.51.100.77',$tail='"-" "fixture"'){return $ip.' - - [] "GET '.$t.' HTTP/1.1" '.$status.' 10 '.$tail;}
$positive=["/index.php?rp=store' ORDER BY 1000-- -","/index.php?rp=store AND EXTRACTVALUE(6265,CONCAT(0x7e,((SELECT (ELT(6265=6265,1)))),0x7e))-- -","/index.php?rp=') AND ('cweigq'='cweigq''","/cart.php?a=add&domain=register' UNION ALL SELECT 'token',NULL-- abc"];
foreach($positive as $t){$encoded=str_replace([' ',"'",'(',')',',','='],['%20','%27','%28','%29','%2C','%3D'],explode('?',$t,2)[1]);$path=explode('?',$t,2)[0];foreach([$path.'?'.$encoded,$path.'?'.str_replace('%','%25',$encoded)] as $raw)foreach([200,302,400,403,404,421,500] as $status)foreach(['198.51.100.77','2001:db8::77'] as $ip){$line=sqlLine($raw,$status,$ip);sqlCheck(SqlInjection::fromLine($line),'Closed SQL lost');sqlCheck(!RequestEvidence::nonOffensiveLine($line),'Normal route overrode payload');sqlCheck(AttackFamily::fromLine($line)==='sql-injection','Family missing');}}
foreach(['/index.php','/cart.php?a=add&domain=register','/index.php?note=EXTRACTVALUE','/index.php?note=ORDER%20BY%201','/index.php?doc=UNION%20SELECT','/cart.php?file=report.csv','/callback.php?payment=approved','/EXTRACTVALUE(1,SELECT)/index.php','/index.php?note=EXTRACTVALUE%281%29'] as $t){$line=sqlLine($t,500,'198.51.100.77','"EXTRACTVALUE" "GET /cart.php?a=UNION SELECT NULL-- x HTTP/1.1"');sqlCheck(!SqlInjection::fromLine($line),'Header/keyword authorized SQL');}
sqlCheck(!SqlInjection::fromLine('prefix '.sqlLine('/index.php?x=UNION%20SELECT%20NULL--')),'Forged prefix');
sqlCheck(!SqlInjection::target('/index.php?'.str_repeat('x',8192)),'Oversize');
echo "PASS: {$n} closed SQL query and normal-route precedence checks; no SQL/provider/native\n";
