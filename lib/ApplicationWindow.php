<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Recent observation context only. Never schedules work or acknowledges historical rows. */
final class ApplicationWindow
{
    public const KEYS=['ai_application_probe_history_enabled','ai_application_probe_history_rows'];
    public static function enabled(): bool {
        return (int)Database::getConfig('schema_version','0')>=31&&ProbeApplications::enabled()
            &&Policy::number('ai_application_probe_history_enabled')===1;
    }
    public static function attach(array $work): array {
        $php=PhpScan::grouped($work['pattern']??'');
        $enabled=$php?((int)Database::getConfig('schema_version','0')>=35&&Policy::number('ai_php_scan_history_enabled')===1):self::enabled();
        if(!$enabled||(!$php&&!ProbeApplications::grouped($work['pattern']??''))||empty($work['_work_events'])
            ||!in_array($work['source_log']??'',ProbeSimulation::SOURCES,true))return $work;
        if(Safety::isWhitelisted($work['ip']??'',AutoBanEngine::loadWhitelist()))return $work;
        $now=time();$cutoff=max(RecentActivity::cutoff(),$now-Policy::number($php?'ai_php_scan_window_minutes':'ai_application_probe_window_minutes')*60);
        $limit=Policy::number($php?'ai_php_scan_history_rows':'ai_application_probe_history_rows');
        $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$work['ip'])->where('source_log',$work['source_log'])
            ->where('pattern',$work['pattern'])->where('processing_state','processed')->whereColumn('revision','analyzed_revision')
            ->where('analyzed_revision','>',0)->whereNull('blocked_confirmed_at')->where('last_event_at','>=',date('Y-m-d H:i:s',$cutoff))
            ->orderByDesc('last_event_at')->orderBy('id')->limit($limit)->get()->map(fn($r)=>(array)$r)->all();
        if(!$rows)return $work;
        $decisions=Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('ip',$work['ip'])->where('source_log',$work['source_log'])
            ->where('pattern',$work['pattern'])->whereIn('classification',['monitor','ban'])->whereIn('status',['pending','rejected'])
            ->where(fn($q)=>$q->where('created_at','>=',date('Y-m-d H:i:s',$cutoff))->orWhere('updated_at','>=',date('Y-m-d H:i:s',$cutoff))->orWhere('resolved_at','>=',date('Y-m-d H:i:s',$cutoff)))
            ->orderByDesc('updated_at')->orderByDesc('id')->limit(101)->get(['classification','status','evidence'])->map(fn($r)=>(array)$r)->all();
        if(count($decisions)>100)return $work; // Do not miss a rejection outside the bounded read.
        $approved=[];$rejected=[];$bytes=0;
        foreach($decisions as $d){$bytes+=strlen($d['evidence']??'');if($bytes>2097152)return $work;
            foreach(DecisionProtection::lines($d) as $line){$hash=hash('sha256',$line);
                if($d['status']==='rejected')$rejected[$hash]=true;
                elseif($d['classification']==='monitor')$approved[$hash]=true;
            }
        }
        return self::expand($work,$rows,array_diff_key($approved,$rejected),$now,$limit);
    }
    /** Pure bounded selection. Raw source IDs survive; historical refs are not completion refs. */
    public static function expand(array $work,array $rows,array $approved,int $now,int $limit=32): array {
        $current=$work['_work_events']??[];
        $php=PhpScan::grouped($work['pattern']??'');
        if(!$current||(!$php&&!ProbeApplications::grouped($work['pattern']??'')))return $work;
        $cutoff=max(RecentActivity::cutoff(),$now-Policy::number($php?'ai_php_scan_window_minutes':'ai_application_probe_window_minutes')*60);
        $pool=[];$apps=[];$bytes=0;
        foreach(array_slice($rows,0,min(100,$limit)) as $r){
            if(($r['ip']??'')!==$work['ip']||($r['source_log']??'')!==$work['source_log']||($r['pattern']??'')!==$work['pattern']
                ||($r['processing_state']??'')!=='processed'||(int)($r['revision']??0)<1
                ||(int)$r['revision']!==(int)($r['analyzed_revision']??-1)||!empty($r['blocked_confirmed_at'])
                ||($r['decision_state']??'')==='rejected')continue;
            $raw=$r['samples']??'[]';$bytes+=strlen($raw);if($bytes>2097152)break;
            $samples=json_decode($raw,true);if(!is_array($samples)||!array_is_list($samples))continue;
            foreach($samples as $e){$line=$e['line']??null;
                if(!is_string($line)||strlen($line)>65535||str_contains($line,"\n")||str_contains($line,"\r")||!empty($e['truncated']))continue;
                $hash=hash('sha256',$line);$t=BehaviorStore::eventTime($line);
                if(!isset($approved[$hash])||!is_string($e['id']??null)||!preg_match('/^[a-f0-9]{64}$/D',$e['id'])
                    ||($e['ip']??'')!==$work['ip']||($e['pattern']??'')!==$work['pattern']
                    ||(isset($e['source_log'])&&$e['source_log']!==$work['source_log'])
                    ||!$t||$t!==($e['time']??null)||$t<$cutoff||$t>$now||Safety::sourceIp($line)!==$work['ip'])continue;
                $app=$php?PhpScan::target($line):ProbeApplications::application($line,ProbeApplications::groups());if($app===null)continue;
                $pool[$hash]=['event'=>$e,'app'=>$app,'row'=>['id'=>$r['id'],'revision'=>(int)$r['revision']]];$apps[$app]=true;
            }
        }
        $new=$php?array_values(array_unique(array_filter(array_map(fn($e)=>PhpScan::target($e['line']??''),$current)))):ProbeApplications::stats($current,$work['ip'],$cutoff)['groups'];
        if(!$pool||!array_diff($new,array_keys($apps)))return $work; // Repetition alone is not novelty.
        $seen=[];$ids=[];$size=0;$selected=[];$groups=[];$refs=[];
        foreach($current as $e){$seen[hash('sha256',$e['line'])]=true;$ids[$e['id']]=$e['line'];$size+=strlen($e['line']);
            if($app=$php?PhpScan::target($e['line']):ProbeApplications::application($e['line'],ProbeApplications::groups()))$groups[$app]=true;}
        // Prefer one representative per distinct application, then remaining complete events.
        for($pass=0;$pass<2;$pass++)foreach($pool as $hash=>$p){$e=$p['event'];
            if(isset($seen[$hash])||($pass===0&&isset($groups[$p['app']])))continue;
            if(isset($ids[$e['id']])&&$ids[$e['id']]!==$e['line'])continue;
            if(count($current)+count($selected)>=AnalysisWork::MAX_EVENTS||$size+strlen($e['line'])>AnalysisWork::MAX_BYTES)continue;
            $seen[$hash]=true;$ids[$e['id']]=$e['line'];$groups[$p['app']]=true;$size+=strlen($e['line']);$selected[]=$e;
            $refs[$p['row']['id']]=$p['row'];
        }
        if($selected){$work['_work_events']=array_merge($current,$selected);$work['_work_window_refs']=array_values($refs);}
        return $work;
    }
}
