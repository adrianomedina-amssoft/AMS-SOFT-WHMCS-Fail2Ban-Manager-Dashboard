<?php
/** Explicit root CLI only. No hooks, scheduling, providers or automatic maintenance. */
if(PHP_SAPI!=='cli'||!function_exists('posix_geteuid')||posix_geteuid()!==0)exit(1);
$options=getopt('',['preview','apply','resume','backup:','job:']);
require_once dirname(__DIR__).'/lib/AutoindexJournal.php';$mode=\AMS\Fail2Ban\AutoindexJournal::mode($options);
$backup=realpath($options['backup']);
if(!$backup||!str_starts_with($backup,'/var/backups/amssoft_fail2ban/')||fileowner($backup)!==0||(fileperms($backup)&0077)!==0)throw new RuntimeException('Backup privado root exigido.');
require dirname(__DIR__,4).'/configuration.php';require dirname(__DIR__,4).'/vendor/autoload.php';require dirname(__DIR__).'/lib/Router.php';
use WHMCS\Database\Capsule as C;use AMS\Fail2Ban\{AutoindexReview,AutoindexRetention,AutoindexJournal,Database,Policy,DecisionProtection,Privileged};
$c=new C;$c->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4']);$c->setAsGlobal();$c->bootEloquent();date_default_timezone_set('America/Sao_Paulo');
function nativeReviewTickets(): array {
    $code="import runpy,json;h=runpy.run_path('/usr/local/sbin/amsfb-admin');s=dict(h['native_command'](['status']));print(json.dumps(h['tickets'](s['Jail list'].split(', '),native=True)))";
    $p=proc_open(['/usr/bin/python3','-c',$code],[1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p))throw new RuntimeException('Leitura nativa indisponível.');
    $out=stream_get_contents($pipes[1]);fclose($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[2]);
    if(proc_close($p)!==0||$err!=='')throw new RuntimeException('Tickets nativos não confirmados.');return json_decode($out,true,512,JSON_THROW_ON_ERROR);
}
$db=C::connection();$cycle=$policy=false;
try{
    $cycle=(int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired===1;if(!$cycle)throw new RuntimeException('Ciclo ocupado.');
    $policy=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;if(!$policy)throw new RuntimeException('Política ocupada.');
    $job=$mode==='preview'?bin2hex(random_bytes(16)):$options['job'];$directory=$backup.'/autoindex-v2-'.$job;
    $tickets=nativeReviewTickets();$targets=array_values(array_filter($tickets,fn($t)=>in_array($t['jail'],AutoindexReview::JAILS,true)));
    if($mode!=='preview')$targets=AutoindexJournal::read($directory.'/manifest.json')['approved'];
    $ips=array_values(array_unique(array_column($targets,'ip')));$now=time();
    $scan=AutoindexRetention::scan('/var/log/apache2',$ips,Policy::number('autoindex_review_days'),Policy::number('autoindex_review_lookback_hours'),$now);
    $ai=[];$decisions=C::table('mod_amssoft_fail2ban_ai_suggestions')->whereIn('ip',$ips)->where('classification','ban')->where('status','!=','rejected')->orderBy('id')->limit(1001)->get(['id','ip','status']);
    if(count($decisions)>1000)$scan['retention']['status']='unknown';foreach($decisions as $r)$ai[$r->ip][]=(array)$r;
    $assess=static fn($t,$live)=>AutoindexReview::assess($t,$live,$scan['events'][$t['ip']]??[],$ai[$t['ip']]??[],$scan['retention'],time());
    if($mode==='preview'){
        $results=[];$approved=[];foreach($targets as $t){$a=$assess($t,$tickets);$results[]=$t+$a;if($a['eligible'])$approved[]=$t;}
        AutoindexJournal::create($directory,['job'=>$job,'at'=>date('c'),'approved'=>$approved,'results'=>$results,'scan'=>$scan,'tickets'=>$tickets]);
        echo json_encode(['job'=>$job,'examined'=>count($targets),'eligible'=>count($approved),'retention'=>$scan['retention']['status'],'reasons'=>$scan['retention']['reasons']]),"\n";exit;
    }
    AutoindexJournal::write($directory.'/recheck-'.bin2hex(random_bytes(8)).'.json',['at'=>date('c'),'scan'=>$scan,'tickets'=>$tickets]);
    $summary=AutoindexJournal::run($directory,'nativeReviewTickets',$assess,static fn()=>AutoindexRetention::unchanged($scan['retention'],time()),
        static fn($t)=>Privileged::run(['unban-ticket',$t['jail'],$t['ip'],$t['ticket']]),
        static function($t,$i,$status)use($job){$reason='Autoindex job '.$job.' ticket '.$i.': '.$status.'; identidade e retenção revalidadas.';
            if(!C::table('mod_amssoft_fail2ban_logs')->where('ip',$t['ip'])->where('jail',$t['jail'])->where('action','unban')->where('reason',$reason)->exists())Database::logEvent($t['ip'],$t['jail'],'unban',$reason);
        },time());
    $removed=array_values(array_filter($summary['results'],fn($r)=>in_array($r['status'],['removed','absent_after_intent'],true)));
    $removedIps=array_values(array_unique(array_column(array_column($removed,'target'),'ip')));$coverage=$removedIps?DecisionProtection::snapshot($removedIps):[];$confirmed=0;
    foreach($removedIps as $ip)if(DecisionProtection::classify(['ip'=>$ip,'source_log'=>'/var/log/apache2/access.log'],$coverage)['state']==='unprotected')$confirmed++;
    $rows=array_map(fn($r)=>$r['target']+['result'=>$r['status'],'reason'=>$r['reason']??''],$summary['results']);$manifest=AutoindexJournal::read($directory.'/manifest.json');
    $report=['at'=>date('c'),'job'=>$job,'examined_tickets'=>count($manifest['results']),'released_tickets'=>count($removed),'released_ips'=>$confirmed,
        'release_unconfirmed_ips'=>count($removedIps)-$confirmed,'results'=>array_slice($rows,0,25),'complete'=>$summary['complete'],'retention'=>$scan['retention']['status'],'error'=>$summary['error']];
    AutoindexJournal::write($directory.'/report-'.bin2hex(random_bytes(8)).'.json',$report);Database::setConfig('autoindex_review_report',json_encode($report));echo json_encode($report),"\n";
    if($summary['error'])throw new RuntimeException('Manutenção parcial; diário preservado. Use --resume com o mesmo job.');
}finally{if($policy)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");if($cycle)$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
