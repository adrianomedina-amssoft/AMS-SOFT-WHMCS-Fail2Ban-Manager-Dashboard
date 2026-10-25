<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/ProbeApplications.php';
require_once __DIR__.'/PhpScan.php';
require_once __DIR__.'/LogCursor.php';

use WHMCS\Database\Capsule;

/** Durable local ingestion. Provider availability never owns the log cursor. */
final class BehaviorStore
{
    public static function paths(): array
    {
        $extra=[]; $effective=Privileged::run(['effective-config']);
        if(empty($effective['success'])) throw new \RuntimeException('Configuração efetiva indisponível.');
        foreach($effective['jails'] as $jail=>$cfg) {
            foreach(preg_split('/\s+/', $cfg['logpath']??'',-1,PREG_SPLIT_NO_EMPTY) as $path)
                foreach(glob($path)?:[$path] as $file) $extra[$file]=$jail;
        }
        $paths=[];
        foreach((new LogViewer())->getAvailableLogs($extra) as $log) {
            $real=realpath($log['path']);
            if($real && str_starts_with($real,'/var/log/') && $real!=='/var/log/fail2ban.log' && is_readable($real)) $paths[$real]=$real;
        }
        return array_values($paths);
    }

    public static function eventTime(string $line): ?int
    {
        if(preg_match('~^\S+\s+-\s+\S+\s+\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]~',$line,$m)) {
            $date=\DateTimeImmutable::createFromFormat('d/M/Y:H:i:s O',$m[1]);
            return $date?$date->getTimestamp():null;
        }
        if(preg_match('/^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)(?=\s|$)/',$line,$m))
            return strtotime(str_replace(',', '.', $m[1]))?:null;
        if(preg_match('/^\[([A-Za-z]{3} [A-Za-z]{3}\s+\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)? \d{4})\]/',$line,$m)) {
            $date=\DateTimeImmutable::createFromFormat(str_contains($m[1],'.')?'D M j H:i:s.u Y':'D M j H:i:s Y',$m[1]);
            return $date?$date->getTimestamp():null;
        }
        if(preg_match('/^([A-Za-z]{3}\s+\d{1,2} \d\d:\d\d:\d\d)\s/',$line,$m)) {
            $value=strtotime($m[1].' '.date('Y'));
            if($value && $value>time()+86400)$value=strtotime($m[1].' '.((int)date('Y')-1));
            return $value?:null;
        }
        // Unknown dates are not manufactured as recent evidence.
        return null;
    }

    public static function pattern(string $line): string
    {
        if(preg_match('~"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^ ]+) HTTP/[^"]+" (\d{3})~',$line,$m)) {
            $path=rawurldecode(explode('?',$m[2],2)[0]);
            $path=preg_replace('/[a-f0-9]{16,}|\b\d+\b/i','{id}',$path);
            $query=rawurldecode(explode('?',$m[2],2)[1]??'');
            $signature=preg_match('/union\s+(?:all\s+)?select|sleep\s*\(|benchmark\s*\(|or\s+1\s*=\s*1/i',$query)?' sql-probe':'';
            if(preg_match('~\.\./|/etc/passwd|(?:\$\(|;|\|)\s*(?:wget|curl|sh|bash)~i',$query))$signature.=' traversal-command';
            return hash('sha256',$m[1].' '.$path.' '.substr($m[3],0,1).$signature);
        }
        return hash('sha256',preg_replace('/[0-9a-f:.]{4,}|\d+/i','*',$line));
    }

    public static function collect(string $path): array
    {
        $lock=LogLock::acquire($path);
        if(!$lock['fp']) return ['log'=>$path,'mode'=>'locked'];
        try {
            $key='adaptive_cursor.'.md5($path);
            $cursor=json_decode(Database::getConfig($key,''),true);
            $read=LogCursor::read($path,$cursor,Policy::number('ai_log_lines'));
            $cursor=$read['cursor'];
            if($read['mode']==='initialized_at_eof'){
                Database::setConfig($key,json_encode($cursor,JSON_THROW_ON_ERROR));
                return ['log'=>$path,'mode'=>'initialized_at_eof'];
            }
            $events=[];$retentionCutoff=time()-Policy::number('ai_rollup_retention_hours')*3600;
            $whitelist=AutoBanEngine::loadWhitelist();
            $applicationGroups=ProbeApplications::enabled()?ProbeApplications::groups():[];
            $applicationPattern=$applicationGroups?ProbeApplications::pattern($applicationGroups):null;
            $phpScan=PhpScan::enabled();
            $retiredPaths=RetiredRoutes::paths();$locallyObserved=0;
            foreach($read['records'] as $record){
                $line=$record['line'];$ip=Safety::sourceIp($line);$time=self::eventTime($line);
                if(!$ip||!$time||$time>time()+300 || $time<$retentionCutoff
                    ||Safety::isWhitelisted($ip,$whitelist)) continue;
                $pattern=$applicationGroups&&ProbeApplications::application($line,$applicationGroups)!==null?$applicationPattern:self::pattern($line);
                if($phpScan&&PhpScan::target($line,true)!==null)$pattern=PhpScan::pattern();
                $events[]=['id'=>hash('sha256',$path."\0".$record['file']."\0".$record['generation']."\0".$record['offset']),
                    'ip'=>$ip,'line'=>mb_convert_encoding($line,'UTF-8','UTF-8'),'time'=>$time,'pattern'=>$pattern];
            }
            Capsule::connection()->transaction(function()use($events,$path,$key,$cursor,$retiredPaths,$read,&$locallyObserved){
                $groups=[];
                foreach($events as $event) {
                    $bucket=date('Y-m-d H:i:s',(int)(floor($event['time']/600)*600));
                    $id=hash('sha256',$path."\0".$event['ip']."\0".$event['pattern']."\0".$bucket);
                    if(!isset($groups[$id])) $groups[$id]=['ip'=>$event['ip'],'pattern'=>$event['pattern'],'bucket'=>$bucket,'events'=>[]];
                    $groups[$id]['events'][]=$event;
                }
                foreach($groups as $id=>$group) {
                    $row=Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->lockForUpdate()->first();
                    $samples=$row?json_decode($row->samples,true):[];
                    $allSamples=array_merge($samples?:[],$group['events']);
                    $samples=PhpScan::grouped($group['pattern'])?PhpScan::samples($allSamples):
                        (ProbeApplications::grouped($group['pattern'])?ProbeApplications::samples($allSamples):array_slice($allSamples,-5));
                    // Five bounded samples only, never the full request stream.
                    while(strlen(json_encode($samples,JSON_INVALID_UTF8_SUBSTITUTE))>262144) array_shift($samples);
                    $values=['ip'=>$group['ip'],'source_log'=>$path,'pattern'=>$group['pattern'],'bucket'=>$group['bucket'],
                        'events'=>($row->events??0)+count($group['events']),'revision'=>($row->revision??0)+1,
                        'samples'=>json_encode($samples,JSON_INVALID_UTF8_SUBSTITUTE),'updated_at'=>date('Y-m-d H:i:s'),
                        'processing_state'=>'pending','validation_attempts'=>0,'attempts'=>0,'retry_at'=>null,
                        'failure_code'=>null,'failure_detail'=>null];
                    if(RecentActivity::enabled())$values['last_event_at']=max(date('Y-m-d H:i:s',max(array_column($group['events'],'time'))),(string)($row->last_event_at??''));
                    if($row && $row->revision>$row->analyzed_revision) {
                        // The overlay family never changes the task identity.
                        // More traffic is not a new validation budget for unfinished work.
                        foreach(['processing_state','validation_attempts','attempts','retry_at','failure_code','failure_detail'] as $field)
                            $values[$field]=$row->$field;
                    }
                    if((int)Database::getConfig('schema_version','0')>=21)$values['family_key']=AttackFamily::fromLine($group['events'][0]['line']);
                    if((int)Database::getConfig('schema_version','0')>=23) {
                        $variants=$row?json_decode($row->behavior_variants??'null',true):[];
                        $complete=!$row||!empty($row->behavior_complete);
                        if($row&&$variants===null) {
                            $previous=json_decode($row->samples,true)?:[];
                            $complete=count($previous)>=$row->events;$variants=[];
                            if($complete)foreach($previous as $event) {
                                $hash=DecisionMemory::lineSignature($event['line'],$group['ip']);
                                if(!$hash){$complete=false;break;}$variants[]=$hash;
                            }
                        }
                        foreach($group['events'] as $event) {
                            $hash=PhpScan::grouped($group['pattern'])?PhpScan::signature($event['line'],$group['ip']):(ProbeApplications::grouped($group['pattern'])?ProbeApplications::signature($event['line'],$group['ip']):DecisionMemory::lineSignature($event['line'],$group['ip']));
                            if(!$hash){$complete=false;break;}$variants[]=$hash;
                        }
                        $variants=array_values(array_unique($variants?:[]));sort($variants,SORT_STRING);
                        if(count($variants)>16)$complete=false;
                        $values['behavior_variants']=json_encode(array_slice($variants,0,16));
                        $values['behavior_complete']=$complete?1:0;
                    }
                    $local=RetiredRoutes::recordable($row?(array)$row:null,$group['events'],$path,$retiredPaths);
                    if($local){$values['analyzed_revision']=$values['revision'];$values['processing_state']='observed_local';$values['retry_at']=null;$values['attempts']=0;$values['validation_attempts']=0;$values['failure_code']=null;$values['failure_detail']=null;$locallyObserved+=count($group['events']);}
                    if(!$local&&($simple=LocalObservation::recordable($row?(array)$row:null,$group['events'],$path))!==null){
                        $values['analyzed_revision']=$values['revision'];$values['processing_state']='observed_'.$simple;$values['retry_at']=null;
                        $values['attempts']=0;$values['validation_attempts']=0;$values['failure_code']=null;$values['failure_detail']=null;$locallyObserved+=count($group['events']);
                    }
                    if($row) Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->update($values);
                    else Capsule::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id]+$values);
                    if((int)Database::getConfig('schema_version','0')>=19 && QueueTelemetry::entersQueue($row?(array)$row:null,$values))
                        Database::incrementConfig('ai_queue_entries_total');
                }
                self::revisitCampaigns(array_unique(array_column($groups,'pattern')));
                foreach($read['diagnostics'] as $diagnostic)
                    Database::logEvent('','',$diagnostic['action'],'Coleta: '.$path.' ['.$diagnostic['code'].']; timestamps originais preservados.');
                if($read['oversized'])Database::logEvent('','','log_input_limit','Linhas/chunks excessivos ignorados: '.$path.' ('.$read['oversized'].')');
                Database::setConfig($key,json_encode($cursor));
            });
            return ['log'=>$path,'mode'=>'collected','lines'=>$read['lines'],'events'=>count($events),
                'local_observed'=>$locallyObserved,'offset'=>$cursor['offset'],'more'=>$read['more'],
                'previous_generations'=>count($cursor['previous'])];
        } finally { LogLock::release($lock['fp']); }
    }

    public static function pending(int $limit=10,?bool $retry=null,bool $urgent=false,bool $distinct=false): array
    {
        $query=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
            ->where('processing_state','!=','review')
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
            ->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s')));
        if($retry!==null)$query->where('attempts',$retry?'>':'=',0);
        RecentActivity::query($query);
        self::withoutHeld($query);
        if($urgent&&RecentActivity::enabled()){
            $candidates=(clone $query)->orderByDesc('last_event_at')->orderBy('id')->limit(500)->get()->map(fn($r)=>(array)$r)->all();
            $out=[];$ips=[];foreach($candidates as $r){
                $suspect=SensitiveTargets::priority($r)||PhpScan::priority($r)||((int)Database::getConfig('schema_version','0')>=36&&LocalObservation::priority($r))||Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('ip',$r['ip'])
                    ->where('source_log',$r['source_log'])->where('classification','ban')->where('status','pending')
                    ->whereIn('severity',['high','critical'])->where('confidence','>=',Policy::number('ai_auto_min_confidence'))->exists();
                if(!$suspect||($distinct&&isset($ips[$r['ip']])))continue;
                $out[]=$r;$ips[$r['ip']]=true;if(count($out)>=$limit)break;
            }return $out;
        }
        if($urgent) $query->whereExists(function($q){
            $q->selectRaw('1')->from('mod_amssoft_fail2ban_ai_suggestions as s')
                ->whereColumn('s.ip','mod_amssoft_fail2ban_rollups.ip')
                ->whereColumn('s.source_log','mod_amssoft_fail2ban_rollups.source_log')
                ->where('s.status','pending')->where('s.classification','ban')
                ->where('s.confidence','>=',Policy::number('ai_auto_min_confidence'));
            if((int)Database::getConfig('schema_version','0')>=24){
                $q->whereIn('s.severity',['high','critical'])->whereExists(function($proof){
                    $proof->selectRaw('1')->from(EvidenceLinks::TABLE.' as priority_link')
                        ->join('mod_amssoft_fail2ban_detections as priority_detection','priority_detection.fingerprint','=','priority_link.fingerprint')
                        ->whereColumn('priority_link.suggestion_id','s.id')->where('priority_link.validation_state','valid')
                        ->where('priority_link.confidence','>=',Policy::number('ai_auto_min_confidence'))
                        ->where('priority_detection.validation_state','valid')->whereColumn('priority_detection.ip','s.ip')
                        ->whereColumn('priority_detection.source_log','s.source_log')
                        ->where('priority_detection.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
                });
            }else{$q->whereColumn('s.pattern','mod_amssoft_fail2ban_rollups.pattern')->whereColumn('s.task_id','mod_amssoft_fail2ban_rollups.id');}
        })->orderByDesc('bucket');
        else $query->orderBy('bucket');
        $query->orderBy('id');
        if(!$distinct)return $query->limit($limit)->get()->map(fn($r)=>(array)$r)->all();
        $result=[];$seen=[];
        while(count($result)<$limit) {
            $page=clone $query;
            if($seen)$page->whereNotIn('ip',array_keys($seen));
            $rows=$page->limit(min(100,$limit-count($result)))->get();
            if($rows->isEmpty())break;
            foreach($rows as $row)if(!isset($seen[$row->ip])){$seen[$row->ip]=true;$result[]=(array)$row;}
        }
        return $result;
    }

    public static function defer(array $row,string $code='provider_partial',string $detail='Classificação ausente ou não vinculada à tarefa.'): void
    {
        $attempts=min(12,(int)$row['attempts']+1);
        $values=[
            'processing_state'=>'retry','failure_code'=>$code,'failure_detail'=>mb_substr($detail,0,500),
            'attempts'=>$attempts,'retry_at'=>date('Y-m-d H:i:s',time()+min(3600,60*(2**min(6,$attempts))))];
        Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])->whereColumn('revision','>','analyzed_revision')->update($values);
    }

    public static function validationFailed(array $row,array $diagnostic): void
    {
        if(($diagnostic['code']??'bridge_error')==='bridge_error') {
            self::defer($row,'validation_bridge','Validador indisponível; não indica filtro inseguro.');return;
        }
        $attempts=(int)($row['validation_attempts']??0)+1;
        self::defer($row,$diagnostic['code'],$diagnostic['error']??'Filtro recusado.');
        $values=['validation_attempts'=>$attempts,'processing_state'=>$attempts>=Policy::number('ai_validation_max_attempts')?'review':'retry'];
        if((int)Database::getConfig('schema_version','0')>=19) {
            $values['total_validation_attempts']=Capsule::raw('total_validation_attempts+1');
            $values['validation_generation']=AIAnalyzer::RECOVERY_GENERATION;
        }
        Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])->whereColumn('revision','>','analyzed_revision')->update($values);
    }

    /** Called only by the automatic worker while it owns the cycle/policy locks. */
    public static function recoverReviews(): int
    {
        if((int)Database::getConfig('schema_version','0')<19||Policy::number('ai_review_auto_recovery_enabled')!==1||CycleBudget::remaining()<2)return 0;
        $generation=AIAnalyzer::RECOVERY_GENERATION;$limit=Policy::number('ai_review_recovery_limit');
        return Capsule::connection()->transaction(function()use($generation,$limit){
            $cursor=json_decode(Database::getConfig('ai_review_recovery_cursor','null'),true);
            $query=Capsule::table('mod_amssoft_fail2ban_rollups')->where('processing_state','review')
                ->whereColumn('revision','>','analyzed_revision')
                ->whereIn('failure_code',['filter_citation','filter_host','filter_positive','filter_identity','filter_branch','filter_peer','filter_syntax','filter_missing','filter_evidence','filter_definition','filter_legitimate'])
                ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
                ->where(fn($q)=>$q->whereNull('recovery_generation')->orWhere('recovery_generation','!=',$generation)->orWhere('recovery_rounds','<',$limit))
                ->where(fn($q)=>$q->whereNull('validation_generation')->orWhere('validation_generation','!=',$generation)
                    ->orWhere(fn($q)=>$q->where('recovery_generation',$generation)->where('recovery_rounds','<',$limit)))
                ->orderBy('bucket')->orderBy('id');
            if(is_array($cursor)&&($cursor['generation']??null)===$generation&&isset($cursor['bucket'],$cursor['id']))
                $query->where(fn($q)=>$q->where('bucket','>',$cursor['bucket'])->orWhere(fn($q)=>$q->where('bucket',$cursor['bucket'])->where('id','>',$cursor['id'])));
            // Suspension never spends a recovery round. Cursor may wrap normally.
            self::withoutHeld($query);
            $rows=$query->limit(100)->lockForUpdate()->get();
            $count=0;$last=null;$inspected=0;
            foreach($rows as $r) {
                if(CycleBudget::remaining()<2)break;
                $last=['generation'=>$generation,'bucket'=>$r->bucket,'id'=>$r->id];$inspected++;
                if(!self::proofEvents((array)$r))continue;
                $round=$r->recovery_generation===$generation?(int)$r->recovery_rounds+1:1;
                Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r->id)->where('revision',$r->revision)->update([
                    'processing_state'=>'retry','validation_attempts'=>0,'recovery_generation'=>$generation,
                    'recovery_rounds'=>$round,'last_recovery_at'=>date('Y-m-d H:i:s')]);
                Database::logEvent($r->ip,'','queue_auto_recovered',json_encode(['task_id'=>$r->id,'generation'=>$generation,'round'=>$round,'previous_code'=>$r->failure_code]));
                $count++;
            }
            // Even unprovable tasks advance the bounded scan. Wrap on the next cycle.
            if($inspected===count($rows)&&count($rows)<100)$last=null;
            elseif($inspected===0&&count($rows)>0)$last=$cursor;
            Database::setConfig('ai_review_recovery_cursor',json_encode($last));
            return $count;
        });
    }

    public static function noteAttempt(array $row): void
    {
        if((int)Database::getConfig('schema_version','0')>=19)
            Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])
                ->whereColumn('revision','>','analyzed_revision')->increment('total_attempts');
    }

    public static function requeue(string $id,int $admin): array
    {
        if($admin<1||!preg_match('/^[a-f0-9]{64}$/D',$id))throw new \InvalidArgumentException('Reenvio inválido.');
        return Capsule::connection()->transaction(function()use($id,$admin){
            $row=Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->lockForUpdate()->first();
            $eligibility=self::requeueEligibility($row?(array)$row:[],time(),Policy::number('ai_behavior_hours'));
            if(!$eligibility['allowed'])throw new \InvalidArgumentException($eligibility['reason']);
            Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$id)->update(['processing_state'=>'pending','attempts'=>0,
                'validation_attempts'=>0,'retry_at'=>null,'failure_code'=>null,'failure_detail'=>null]);
            Database::logEvent($row->ip,'','queue_requeued','Revisão reenviada: '.$id,$admin);
            return ['requeued'=>$id,'notice'=>$eligibility['reason']];
        });
    }

    /** Shared read-only predicate for the UI and the locked mutation. */
    public static function requeueEligibility(array $row,int $now,int $memoryHours): array
    {
        if(($row['processing_state']??'')!=='review')return ['allowed'=>false,'reason'=>'Tarefa não está em revisão técnica.'];
        $bucket=isset($row['bucket'])?strtotime($row['bucket']):false;
        if($bucket===false||$bucket>$now||$bucket<$now-$memoryHours*3600)return ['allowed'=>false,'reason'=>'Evidência fora da memória ou horário inválido; aguarde eventos novos.'];
        if(RecentActivity::enabled()){
            $cut=$now-Policy::number('ai_analysis_recent_minutes')*60;
            $last=isset($row['last_event_at'])?strtotime($row['last_event_at']):false;
            if($last===false||$last<$cut||$last>$now+300||RecentActivity::latest($row,$now)<$cut)
                return ['allowed'=>false,'reason'=>'Evidência individual fora da janela recente ou não comprovada; aguarde eventos novos.'];
        }
        return ['allowed'=>true,'reason'=>'Revisão elegível para o cron, sujeita à rechecagem de proteção e recência; nenhum ban executado nesta requisição.'];
    }

    public static function health(): array
    {
        $base=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision');
        $cutoff=date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600);
        $active=(clone $base)->where('bucket','>=',$cutoff);
        $held=(int)Database::getConfig('schema_version','0')>=20?BlockedTasks::health():['held'=>0,'ips'=>0];
        self::withoutHeld($active);
        $awaiting=0;
        if(EvidenceLinks::enabled()&&BlockedTasks::enabled()){
            $awaiting=(clone $active)->whereNotNull('blocked_confirmed_at')->where('blocked_until_check_at','<=',date('Y-m-d H:i:s'))->count();
            $active->whereNull('blocked_confirmed_at');
        }
        $eligible=(clone $active)->where('processing_state','!=','review');
        $cold=RecentActivity::enabled()?(clone $eligible)->where(fn($q)=>$q->whereNull('last_event_at')->orWhere('last_event_at','<',date('Y-m-d H:i:s',RecentActivity::cutoff())))->count():0;
        RecentActivity::query($active);RecentActivity::query($eligible);
        $ready=(clone $eligible)->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s')));
        $oldestEligible=(clone $eligible)->min('bucket');
        $expiry=QueueExpiry::describe(RecentActivity::enabled()?(clone $eligible)->min('last_event_at'):null,
            Policy::number('ai_analysis_recent_minutes'),Policy::number('ai_interval_minutes'),time());
        return ['historical_deferred'=>$cold,'total'=>(clone $base)->count(),'blocked'=>$held,'awaiting_recheck'=>$awaiting,'new'=>(clone $active)->where('processing_state','!=','review')->where('attempts',0)->count(),
            'retry'=>(clone $active)->where('processing_state','!=','review')->where('attempts','>',0)->count(),
            'review'=>(clone $active)->where('processing_state','review')->count(),
            'outside_window'=>(clone $base)->where('bucket','<',$cutoff)->count(),
            'oldest'=>(clone $base)->min('bucket'),'oldest_eligible'=>$oldestEligible,
            'ready'=>(clone $ready)->count(),'backoff'=>(clone $eligible)->where('retry_at','>',date('Y-m-d H:i:s'))->count(),
            'age_alert'=>($oldestEligible && time()-strtotime($oldestEligible)>Policy::number('ai_queue_alert_minutes')*60)||$expiry['warning'],
            'expiry'=>$expiry,
            'revisits_avoided'=>(int)Database::getConfig('ai_revisits_avoided','0'),
            'diagnostics'=>(clone $active)->select('processing_state','failure_code')->selectRaw('COUNT(*) AS tasks')->groupBy('processing_state','failure_code')->get()->map(fn($r)=>(array)$r)->all(),
            'recovery_generation'=>AIAnalyzer::RECOVERY_GENERATION,
            'recovery_generations'=>(int)Database::getConfig('schema_version','0')>=19?Capsule::table('mod_amssoft_fail2ban_rollups')->whereNotNull('recovery_generation')
                ->select('recovery_generation')->selectRaw('COUNT(*) AS tasks, SUM(recovery_rounds) AS rounds')->groupBy('recovery_generation')->get()->map(fn($r)=>(array)$r)->all():null,
            'recovered_tasks'=>(int)Database::getConfig('schema_version','0')>=19?(clone $active)->whereNotNull('last_recovery_at')->count():null];
    }

    private static function withoutHeld($query): void
    {
        if((int)Database::getConfig('schema_version','0')>=20 && Policy::number('ai_skip_effectively_banned')===1)
            $query->where(fn($q)=>$q->whereNull('blocked_until_check_at')->orWhere('blocked_until_check_at','<=',date('Y-m-d H:i:s')));
    }

    /** Only complete, same-subject events can be authority; history() is context. */
    public static function proofEvents(array $row): array
    {
        $events=json_decode($row['samples'],true)?:[];
        $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$row['ip'])->where('source_log',$row['source_log'])
            ->where('pattern',$row['pattern'])->where('id','!=',$row['id'])
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))->orderByDesc('bucket')->limit(8)->get();
        foreach($rows as $r)$events=array_merge($events,json_decode($r->samples,true)?:[]);
        $result=[];$bytes=0;
        foreach($events as $event) {
            if(count($result)>=8||$bytes+strlen($event['line'])>65536)break;
            if(($event['ip']??null)!==$row['ip']||($event['pattern']??null)!==$row['pattern']||($event['time']??0)<time()-Policy::number('ai_behavior_hours')*3600)continue;
            $result[$event['id']]=$event;$bytes+=strlen($event['line']);
        }
        return array_values($result);
    }

    public static function acknowledge(array $row): void
    {
        $campaign=[];
        if((int)Database::getConfig('schema_version','0')>=18)
            $campaign=['campaign_signature'=>self::campaignSignature($row['source_log'],$row['pattern']),
                'campaign_members'=>json_encode(self::campaignMembers($row['source_log'],$row['pattern']))];
        Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])->update([
            'analyzed_revision'=>$row['revision'],'retry_at'=>null,'attempts'=>0,'processing_state'=>'processed',
            'validation_attempts'=>0,'failure_code'=>null,'failure_detail'=>null]+$campaign);
    }

    public static function campaign(string $pattern,?string $source=null): array
    {
        $query=Capsule::table('mod_amssoft_fail2ban_rollups')->where('pattern',$pattern)
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
        if($source!==null)$query=self::campaignScope($source,$pattern);
        return ['events'=>(int)(clone $query)->sum('events'),'ips'=>(int)(clone $query)->distinct()->count('ip')];
    }

    private static function campaignScope(string $source,string $pattern)
    {
        $query=Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
        $family=(int)Database::getConfig('schema_version','0')>=21?Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->where('pattern',$pattern)->whereNotNull('family_key')->value('family_key'):null;
        return $family?$query->where('family_key',$family):$query->where('pattern',$pattern);
    }

    public static function history(string $ip): array
    {
        $rows=Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$ip)
            ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
            ->orderByDesc('bucket')->limit(8)->get();
        $history=[];
        foreach($rows as $row) {
            $compact=LocalObservation::historySummary((array)$row);
            if($compact!==null){$history[]=$compact;continue;}
            $samples=json_decode($row->samples,true)?:[];$last=end($samples);
            $history[]=['bucket'=>$row->bucket,'events'=>$row->events,
                'sample'=>$last?mb_strcut($last['line'],0,400,'UTF-8'):''];
        }
        return $history;
    }

    public static function campaignMembers(string $source,string $pattern): array
    {
        if((int)Database::getConfig('schema_version','0')>=21)return self::validatedCampaign($source,$pattern)->distinct()->orderBy('d.ip')->pluck('d.ip')->all();
        return self::campaignScope($source,$pattern)
            ->distinct()->orderBy('ip')->pluck('ip')->all();
    }

    public static function campaignSignature(string $source,string $pattern): string
    {
        $members=self::campaignMembers($source,$pattern);
        $events=(int)Database::getConfig('schema_version','0')>=21?self::validatedCampaign($source,$pattern)->count():self::campaignScope($source,$pattern)->sum('events');
        $eligible=count($members)>=Policy::number('ai_behavior_min_ips') && $events>=Policy::number('ai_behavior_min_events');
        return hash('sha256',$source."\0".$pattern."\0".($eligible?'1':'0')."\0".implode("\0",$members));
    }

    private static function validatedCampaign(string $source,string $pattern)
    {
        $family=Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$source)->where('pattern',$pattern)->whereNotNull('family_key')->value('family_key');
        if(EvidenceLinks::enabled())return EvidenceLinks::eligible(Capsule::table('mod_amssoft_fail2ban_detections as d'),'d',Policy::number('ai_auto_min_confidence'))
            ->where('d.source_log',$source)->where('d.family_key',$family?:'pattern:'.$pattern)
            ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
        return Capsule::table('mod_amssoft_fail2ban_detections as d')->join('mod_amssoft_fail2ban_ai_suggestions as s','s.id','=','d.suggestion_id')
            ->where('d.source_log',$source)->where('d.family_key',$family?:'pattern:'.$pattern)->where('d.validation_state','valid')
            ->where('d.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))->where('s.classification','ban')->where('s.status','!=','rejected')->where('s.confidence','>=',Policy::number('ai_auto_min_confidence'))
            ->whereRaw('CAST(d.confidence AS UNSIGNED) >= ?',[Policy::number('ai_auto_min_confidence')]);
    }

    public static function revisitCampaigns(array $patterns): void
    {
        if((int)Database::getConfig('schema_version','0')<18||Policy::number('ai_behavior_enabled')!==1||Policy::number('ai_behavior_require_repetition')===1)return;
        $avoided=0;
        foreach($patterns as $pattern) {
            $sources=Capsule::table('mod_amssoft_fail2ban_rollups')->where('pattern',$pattern)->distinct()->pluck('source_log');
            foreach($sources as $source) {
            $scope=self::campaignScope($source,$pattern);
            if((int)Database::getConfig('schema_version','0')>=21){
                $valid=self::validatedCampaign($source,$pattern);
                if((clone $valid)->count()<Policy::number('ai_behavior_min_events')||(clone $valid)->distinct()->count('d.ip')<Policy::number('ai_behavior_min_ips'))continue;
            }elseif((clone $scope)->sum('events')<Policy::number('ai_behavior_min_events')||(clone $scope)->distinct()->count('ip')<Policy::number('ai_behavior_min_ips'))continue;
            $signature=self::campaignSignature($source,$pattern);
            $members=self::campaignMembers($source,$pattern);
            // Revisit already individually suspicious peers when later events
            // reveal a campaign. This is a new review, not a collective ban.
            $candidates=self::campaignScope($source,$pattern)
                ->whereColumn('analyzed_revision','=','revision')->where('processing_state','!=','review')
                ->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s')))
                ->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
                ->whereExists(function($q){
                    $q->selectRaw('1')->from('mod_amssoft_fail2ban_ai_suggestions as s')
                        ->whereColumn('s.ip','mod_amssoft_fail2ban_rollups.ip')
                        ->whereColumn('s.source_log','mod_amssoft_fail2ban_rollups.source_log')
                        ->whereColumn('s.pattern','mod_amssoft_fail2ban_rollups.pattern')
                        ->where('s.status','pending')->where('s.classification','ban')
                        ->where('s.confidence','>=',Policy::number('ai_auto_min_confidence'));
                });
            if((int)Database::getConfig('schema_version','0')>=21)$candidates->whereExists(function($q){
                if(EvidenceLinks::enabled()){
                    $q->selectRaw('1')->from('mod_amssoft_fail2ban_detections as own')
                        ->whereColumn('own.ip','mod_amssoft_fail2ban_rollups.ip')->whereColumn('own.source_log','mod_amssoft_fail2ban_rollups.source_log')
                        ->whereColumn('own.pattern','mod_amssoft_fail2ban_rollups.pattern')
                        ->where('own.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
                    EvidenceLinks::eligible($q,'own',Policy::number('ai_auto_min_confidence'));
                    return;
                }
                $q->selectRaw('1')->from('mod_amssoft_fail2ban_detections as own')
                    ->join('mod_amssoft_fail2ban_ai_suggestions as decision','decision.id','=','own.suggestion_id')
                    ->whereColumn('own.ip','mod_amssoft_fail2ban_rollups.ip')->whereColumn('own.source_log','mod_amssoft_fail2ban_rollups.source_log')
                    ->whereColumn('own.pattern','mod_amssoft_fail2ban_rollups.pattern')->where('own.validation_state','valid')
                    ->where('own.detected_at','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))
                    ->where('decision.classification','ban')->where('decision.status','!=','rejected')->where('decision.confidence','>=',Policy::number('ai_auto_min_confidence'));
            });
            $candidates=$candidates->lockForUpdate()->get();
            foreach($candidates as $row) {
                $previousMembers=json_decode($row->campaign_members??'[]',true)?:[];
                $wasBelowThreshold=$row->campaign_signature===hash('sha256',$source."\0".$pattern."\0".'0'."\0".implode("\0",$previousMembers));
                if($row->campaign_signature===$signature || ($row->campaign_signature && !$wasBelowThreshold && !array_diff($members,$previousMembers))
                    || ($row->last_revisit_at && strtotime($row->last_revisit_at)>time()-Policy::number('ai_campaign_revisit_minutes')*60)) {
                    $avoided++;continue;
                }
                Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->where('revision',$row->revision)
                    ->whereColumn('analyzed_revision','=','revision')->update(['analyzed_revision'=>0,
                        'campaign_signature'=>$signature,'campaign_members'=>json_encode($members),'last_revisit_at'=>date('Y-m-d H:i:s')]);
                if((int)Database::getConfig('schema_version','0')>=19)Database::incrementConfig('ai_queue_entries_total');
            }
            }
        }
        if($avoided)Database::incrementConfig('ai_revisits_avoided',$avoided);
    }

    public static function prune(): void
    {
        if((int)Database::getConfig('schema_version','0')>=19) {
            $outside=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
                ->whereNull('expired_reported_at')->where('bucket','<',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600));
            $count=$outside->update(['expired_reported_at'=>date('Y-m-d H:i:s')]);
            if($count){Database::incrementConfig('ai_queue_expired_total',$count);Database::logEvent('','','queue_outside_window','Tarefas sem conclusão fora da janela: '.$count);}
        }
        $expired=Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')
            ->where('bucket','<',date('Y-m-d H:i:s',time()-Policy::number('ai_rollup_retention_hours')*3600))->count();
        if($expired)Database::logEvent('','','queue_expired','Pendências fora da retenção configurada: '.$expired);
        Capsule::table('mod_amssoft_fail2ban_rollups')->where('bucket','<',date('Y-m-d H:i:s',time()-Policy::number('ai_rollup_retention_hours')*3600))->delete();
        Capsule::table('mod_amssoft_fail2ban_detections')->where('detected_at','<',date('Y-m-d H:i:s',time()-Policy::number('ai_evidence_retention_days')*86400))->delete();
        if(EvidenceLinks::enabled())Capsule::table(EvidenceLinks::TABLE)->whereNotExists(function($q){$q->selectRaw('1')->from('mod_amssoft_fail2ban_detections as kept')->whereColumn('kept.fingerprint',EvidenceLinks::TABLE.'.fingerprint');})->delete();
        Capsule::table('mod_amssoft_fail2ban_jobs')->where('status','preview')->where('created_at','<',date('Y-m-d H:i:s',time()-86400))->delete();
    }

    public static function telemetry(): void
    {
        $path='/var/log/fail2ban.log';
        if(!is_readable($path))return;
        $fp=fopen($path,'rb');if(!$fp)return;
        try {
            $stat=fstat($fp);$identity=$stat['dev'].':'.$stat['ino'];
            $cursor=json_decode(Database::getConfig('native_log_cursor',''),true);
            if(!$cursor) {Database::setConfig('native_log_cursor',json_encode(['file'=>$identity,'offset'=>$stat['size']]));return;}
            $offset=$cursor['file']===$identity&&$cursor['offset']<=$stat['size']?(int)$cursor['offset']:0;
            fseek($fp,$offset);$events=[];$bytes=0;
            while(!feof($fp)&&$bytes<262144) {
                $start=ftell($fp);$line=fgets($fp,65538);if($line===false)break;
                $bytes+=strlen($line);
                if(!str_ends_with($line,"\n")){fseek($fp,$start);break;}
                $offset=ftell($fp);
                $event=self::parseTelemetryLine($line);if($event)$events[]=$event;
            }
            Capsule::connection()->transaction(function()use($events,$identity,$offset){
                foreach($events as $event)Capsule::table('mod_amssoft_fail2ban_logs')->insertOrIgnore($event);
                Database::setConfig('native_log_cursor',json_encode(['file'=>$identity,'offset'=>$offset]));
            });
        } finally {fclose($fp);}
    }

    public static function parseTelemetryLine(string $line): ?array
    {
        if(!preg_match('/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*NOTICE\s+\[([A-Za-z0-9_-]+)\]\s+(Ban|Unban)\s+([0-9a-fA-F:.]+)\s*$/',$line,$m))return null;
        $ip=Safety::canonicalIp($m[4]);if(!$ip)return null;
        return ['ip'=>$ip,'jail'=>$m[2],'action'=>$m[3]==='Ban'?'daemon_ban':'daemon_unban',
            'reason'=>'Telemetria do daemon; pode refletir IA/admin e não constitui evidência de ataque.',
            'timestamp'=>$m[1],'source_event'=>hash('sha256',$line)];
    }
}
