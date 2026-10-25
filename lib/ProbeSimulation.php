<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Local, bounded observation only. No provider, filter promotion or ban authority. */
final class ProbeSimulation
{
    public const EXTRA = [
        'sitecore'=>['/sitecore/shell/sitecore.version.xml'],
        'solr'=>['/solr/','/solr/admin/info/system','/solr/admin/cores'],
        'sugarcrm'=>['/sugar_version.json'],
        'qnap'=>['/cgi-bin/authlogin.cgi'],
        'spring'=>['/actuator/health','/actuator/env'],
        'vmware'=>['/developmentserver/metadatauploader'],
    ];
    public const GROUPS = ['wordpress','exchange','servlet','telerik','servu','coldfusion','zabbix',
        'sitecore','solr','sugarcrm','qnap','spring','vmware'];
    public const KEYS = ['ai_probe_simulation_enabled','ai_probe_simulation_groups',
        'ai_probe_simulation_min_events','ai_probe_simulation_min_apps',
        'ai_probe_simulation_window_minutes','ai_probe_simulation_interval_minutes'];
    public const MAX_ROWS = 500;
    public const MAX_BYTES = 2097152;
    public const SOURCES = ['/var/log/apache2/access.log','/var/log/apache2/access_whmcs.log',
        '/var/log/apache2/access_license_gateway.log'];

    public static function application(string $line,array $groups): ?array
    {
        if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD|POST) [^ "\r\n]+ HTTP/~',$line))return null;
        $target=RequestEvidence::target($line);
        if($target===null)return null;
        $path=strtolower(explode('?',$target,2)[0]);
        foreach($groups as $group)if(in_array($path,(ProbeApplications::CATALOG+self::EXTRA)[$group]??[],true))
            return ['application'=>$group,'path'=>$path];
        return null;
    }

    public static function policy(): array
    {
        $p=[];foreach(self::KEYS as $key)$p[$key]=Database::getConfig($key,(string)Policy::fields()[$key][2]);
        $p['ai_analysis_recent_minutes']=(string)Policy::number('ai_analysis_recent_minutes');
        $p['whitelist_hash']=hash('sha256',json_encode(AutoBanEngine::loadWhitelist()));
        return $p;
    }

    public static function fingerprint(array $policy): string
    {
        ksort($policy,SORT_STRING);return hash('sha256',json_encode($policy));
    }

    /** Counts represented raw events only, never model confidence or campaign neighbours. */
    public static function analyze(array $rows,array $snapshot,array $policy,array $whitelist,int $now): array
    {
        $minutes=min((int)$policy['ai_probe_simulation_window_minutes'],(int)$policy['ai_analysis_recent_minutes']);
        $groups=preg_split('/\s+/',trim($policy['ai_probe_simulation_groups']),-1,PREG_SPLIT_NO_EMPTY);
        $report=['at'=>$now,'policy_hash'=>self::fingerprint($policy),'mode'=>'simulation_only',
            'window_minutes'=>$minutes,'min_events'=>(int)$policy['ai_probe_simulation_min_events'],
            'min_apps'=>(int)$policy['ai_probe_simulation_min_apps'],'rows_examined'=>0,'samples_examined'=>0,
            'partial'=>count($rows)>self::MAX_ROWS,'omitted_events'=>0,'excluded_protected'=>0,
            'excluded_unknown'=>0,'excluded_whitelist'=>0,'subjects'=>0,'criteria_met'=>0,
            'results'=>[],'bans'=>0,'provider_calls'=>0,'status'=>'measured',
            'valid_until'=>min($now+$minutes*60,($snapshot['observed_at']??0)+($snapshot['ttl']??0))];
        if(($snapshot['success']??false)!==true||($snapshot['stable']??false)!==true
            ||!empty($snapshot['errors'])||($snapshot['observed_at']??0)>$now||$report['valid_until']<=$now){
            $report['status']='coverage_unavailable';return $report;
        }
        $subjects=[];$bytes=0;$excluded=[];
        foreach(array_slice($rows,0,self::MAX_ROWS) as $row){
            $ip=Safety::canonicalIp($row['ip']??'');$source=$row['source_log']??'';
            if(!$ip||!Safety::canBan($ip)||!in_array($source,self::SOURCES,true))continue;
            $key=$ip.'|'.$source;
            if(Safety::isWhitelisted($ip,$whitelist)){$excluded[$ip]=true;continue;}
            $raw=$row['samples']??'[]';$bytes+=strlen($raw);
            if($bytes>self::MAX_BYTES){$report['partial']=true;break;}
            $report['rows_examined']++;
            $events=json_decode($raw,true);if(!is_array($events)||!array_is_list($events)){$report['partial']=true;continue;}
            if((int)($row['events']??0)>count($events)){
                $report['omitted_events']+=(int)$row['events']-count($events);$report['partial']=true;
            }
            foreach($events as $e){
                if(!is_array($e))continue;$line=$e['line']??'';$report['samples_examined']++;
                if(!is_string($line)||strlen($line)>65535||str_contains($line,"\n")||str_contains($line,"\r"))continue;
                $t=BehaviorStore::eventTime($line);
                if(!$t||$t<$now-$minutes*60||$t>$now||$t!==($e['time']??null)
                    ||Safety::sourceIp($line)!==$ip||Safety::canonicalIp($e['ip']??'')!==$ip)continue;
                $app=self::application($line,$groups);if(!$app)continue;
                $hash=hash('sha256',$line); // Duplicate citations are not additional requests.
                if(!isset($subjects[$key]))$subjects[$key]=['ip'=>$ip,'source_log'=>$source,'events'=>[],
                    'applications'=>[],'paths'=>[],'latest'=>0];
                $subjects[$key]['events'][$hash]=true;
                $subjects[$key]['applications'][$app['application']]=true;
                $subjects[$key]['paths'][$app['path']]=true;
                $subjects[$key]['latest']=max($subjects[$key]['latest'],$t);
            }
        }
        $report['excluded_whitelist']=count($excluded);
        foreach($subjects as $subject){
            $state=DecisionProtection::classify($subject,$snapshot);
            if($state['state']==='protected'){$report['excluded_protected']++;continue;}
            if($state['state']!=='unprotected'){$report['excluded_unknown']++;continue;}
            $events=count($subject['events']);$apps=count($subject['applications']);
            $met=$events>=$report['min_events']&&$apps>=$report['min_apps'];
            $report['subjects']++;if($met)$report['criteria_met']++;
            $report['results'][]=['ip'=>$subject['ip'],'source_log'=>$subject['source_log'],'events'=>$events,
                'applications'=>$apps,'groups'=>array_keys($subject['applications']),
                'paths'=>array_slice(array_keys($subject['paths']),0,8),'latest'=>$subject['latest'],
                'criteria_met'=>$met,'reason'=>$met?'simulation_criteria_met':'simulation_below_threshold'];
        }
        usort($report['results'],fn($a,$b)=>($b['criteria_met']<=>$a['criteria_met'])
            ?:($b['applications']<=>$a['applications'])?:($b['latest']<=>$a['latest']));
        $report['display_limited']=count($report['results'])>25;
        $report['results']=array_slice($report['results'],0,25);
        return $report;
    }

    /** Independent cron hook. The existing paid worker and its budget are untouched. */
    public static function capture(): void
    {
        if((int)Database::getConfig('schema_version','0')<29||Policy::number('ai_probe_simulation_enabled')!==1)return;
        if((int)Database::getConfig('ai_probe_simulation_last_run','0')+Policy::number('ai_probe_simulation_interval_minutes')*60>time())return;
        $db=Capsule::connection();$cycle=false;$lock=false;
        try{
            $cycle=(int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired")->acquired===1;
            if(!$cycle)return;
            $lock=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',0) AS acquired")->acquired===1;
            if(!$lock)return;
            $policy=self::policy();$now=time();
            $minutes=min((int)$policy['ai_probe_simulation_window_minutes'],(int)$policy['ai_analysis_recent_minutes']);
            $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->whereIn('source_log',self::SOURCES)
                ->where('last_event_at','>=',date('Y-m-d H:i:s',$now-$minutes*60))
                ->orderByDesc('last_event_at')->orderBy('id')->limit(self::MAX_ROWS+1)
                ->get(['id','ip','source_log','samples','events'])->map(fn($r)=>(array)$r)->all();
            // No subjects means no native read is needed, and never a provider call.
            $snapshot=$rows?DecisionProtection::snapshot():['success'=>true,'stable'=>true,'errors'=>[],
                'observed_at'=>time(),'ttl'=>Policy::number('ai_blocked_recheck_seconds'),'entries'=>[],
                'requirements'=>['http'=>[80,443]]];
            $report=self::analyze($rows,$snapshot,$policy,AutoBanEngine::loadWhitelist(),time());
            Database::setConfig('ai_probe_simulation_report',json_encode($report,JSON_UNESCAPED_SLASHES));
            Database::setConfig('ai_probe_simulation_last_run',(string)time());
            Database::setConfig('ai_probe_simulation_error','');
        }catch(\Throwable $e){
            Database::setConfig('ai_probe_simulation_error','Medição local indisponível: '.get_class($e));
        }finally{
            if($lock)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");
            if($cycle)$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");
        }
    }

    /** UI reads the report, never scans logs or starts analysis. */
    public static function read(): array
    {
        $enabled=Policy::number('ai_probe_simulation_enabled')===1;
        $report=json_decode(Database::getConfig('ai_probe_simulation_report','{}'),true)?:[];
        $status=!$enabled?'disabled':(!$report?'awaiting_measurement':($report['status']??'awaiting_measurement'));
        if($enabled&&$report&&($report['policy_hash']??'')!==self::fingerprint(self::policy()))$status='policy_changed';
        elseif($enabled&&$report&&($report['valid_until']??0)<=time()&&$status==='measured')$status='expired';
        return ['enabled'=>$enabled,'status'=>$status,'report'=>$report,
            'error'=>Database::getConfig('ai_probe_simulation_error','')];
    }
}
