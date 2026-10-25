<?php
namespace WHMCS\Database {class Capsule {public static int $calls=0;public static function connection(){self::$calls++;throw new \RuntimeException('SQL unavailable');}}}
namespace {
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{ReportHistory as R,Helper};
$n=0;function report46($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
foreach(['daemon_ban','daemon_unban','policy_changed','logpath_added','native_filter_repaired','future_action','manual_ban','ai_cycle_error'] as $a){$r=R::filters(['action_filter'=>$a]);report46(!$r['errors']&&$r['filters']['action']===$a,'Action preserved '.$a);}
foreach(['ip'=>['192.0.2.1','2001:db8::1'],'date_from'=>['2024-02-29','2026-10-24'],'jail'=>['apache-sensitive','ai-bans'],'page'=>['1','999999999']] as $k=>$values)foreach($values as $v)report46(!R::filters([$k=>$v])['errors'],'Valid '.$k);
foreach(['date_from','date_to','ip','jail','action_filter','page'] as $k)foreach([[],['x'],true,2,new stdClass(),"x\0y",str_repeat('x',1000)] as $v){$r=R::read([$k=>$v]);report46($r['errors']&&$r['total']===null&&!$r['exportable'],'Invalid cannot broaden '.$k);}
report46(\WHMCS\Database\Capsule::$calls===0,'No SQL for bad input');
foreach(['2026-02-29','2026-02-31','2026-13-01','2026-00-01','2026-10-00','9999-12-31','2026-1-01','2026-10-24x'] as $date)report46((bool)R::filters(['date_to'=>$date])['errors'],'Invalid calendar');
foreach(['no-ip','192.0.2','192.0.2.1%','192.0.2.1/24','127.1','1.2.3.999'] as $ip)report46((bool)R::filters(['ip'=>$ip])['errors'],'IP exact only');
report46((bool)R::filters(['date_from'=>'2026-10-25','date_to'=>'2026-10-24'])['errors'],'Inverted range');
report46(!R::filters(['date_from'=>'2026-10-24','date_to'=>'2026-10-24'])['errors'],'Inclusive same day');
foreach(['0','-1','1.5','1e2','1000000000'] as $p)report46((bool)R::filters(['page'=>$p])['errors'],'Invalid page');
$v=R::read([]);report46($v['total']===null&&$v['errors']&&!$v['exportable'],'SQL failure unknown, not zero');
try{R::csv(['ip'=>'bad']);report46(false,'Bad CSV accepted');}catch(InvalidArgumentException $e){report46(true,'Bad CSV blocked');}
foreach(['=1+1','+cmd','-cmd','@SUM(A1)',"\t=1","\r\n+1","\u{FEFF}=1","\u{00a0}@SUM(A1)","\0=1"] as $s)report46(str_starts_with(R::csvCell($s),"'"),'Formula neutralized');
foreach(['normal','192.0.2.1','ação legítima','texto = sem fórmula',"linha1\nlinha2",'"quoted", comma'] as $s)report46(R::csvCell($s)===$s,'Text preserved');
report46(preg_match('//u',R::csvCell("bad\xff"))===1,'UTF8 recovered');report46(!str_contains(R::csvCell("a\0b"),"\0"),'NUL removed');
$fh=fopen('php://temp','w+b');$cells=['ação',"linha\nsegunda",'comma,quote"','\\','=1+1'];fputcsv($fh,array_map([R::class,'csvCell'],$cells),',','"','');rewind($fh);$back=fgetcsv($fh,0,',','"','');fclose($fh);report46($back===array_map([R::class,'csvCell'],$cells),'CSV round trip');
$modulelink='addonmodules.php?module=amssoft_fail2ban';$e=fn($s)=>Helper::e($s);
$view=R::filters([])+['rows'=>[['id'=>1,'timestamp'=>'2026-10-24 00:00:00','ip'=>'192.0.2.1','jail'=>'<svg/onload=x>','action'=>'daemon_ban','reason'=>'<script>alert(1)</script>','admin_id'=>null]],'total'=>1,'pages'=>1,'geo'=>[],'warnings'=>[],'jails'=>['"><script>'],'actions'=>['daemon_ban'],'catalog_limited'=>false,'clock'=>null,'exportable'=>true];
ob_start();include dirname(__DIR__).'/templates/reports_overview.tpl';$html=ob_get_clean();
report46(!str_contains($html,'<script>')&&str_contains($html,'&lt;script&gt;'),'Escaped template');report46(str_contains($html,'não confirma')&&str_contains($html,'cache local'),'Historical scope');report46(str_contains($html,'for="reports-ip"')&&str_contains($html,'aria-label="')===false,'Labels and single page');report46(str_contains($html,'não atribuído')&&!str_contains($html,'>auto<'),'No unsupported auto attribution');
$view['total']=null;$view['rows']=[];$view['exportable']=false;$view['errors']=['Indisponível'];ob_start();include dirname(__DIR__).'/templates/reports_overview.tpl';$html=ob_get_clean();report46(str_contains($html,'Total não confirmado')&&!str_contains($html,'Nenhum evento encontrado'),'Unknown is not empty');report46(!str_contains($html,'do=export_csv'),'No unavailable export');
echo "PASS: $n report filters/CSV/text/error/template checks; no SQL/provider/native\n";
}
