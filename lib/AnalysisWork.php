<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/ProbeApplications.php';
require_once __DIR__.'/PhpScan.php';
require_once __DIR__.'/RecentActivity.php';
require_once __DIR__.'/ApplicationWindow.php';

use WHMCS\Database\Capsule;

/** Scheduling links and parsed-response checkpoints; never creates evidence. */
final class AnalysisWork
{
    public const TABLE = 'mod_amssoft_fail2ban_analysis_work';
    public const BATCH_TABLE = 'mod_amssoft_fail2ban_analysis_batches';
    public const MAX_ROWS = 100;
    public const MAX_EVENTS = 8;
    public const MAX_BYTES = 65536;
    public const MAX_PAYLOAD = 2097152;
    public const CHECKPOINT_TTL = 86400;

    /** Deployment migration only. No runtime method calls this method. */
    public static function migrate(): void
    {
        if (!Capsule::schema()->hasTable(self::TABLE)) Capsule::schema()->create(self::TABLE, static function($t) {
            $t->charset='utf8mb4'; $t->collation='utf8mb4_unicode_ci';
            $t->char('key',64); $t->char('rollup_id',64); $t->unsignedInteger('revision');
            $t->string('result_state',32); $t->timestamp('created_at')->useCurrent();
            $t->primary(['key','rollup_id','revision'],'amsfb_work_pk');
            $t->index(['rollup_id','revision'],'amsfb_work_revision');
        });
        if (!Capsule::schema()->hasTable(self::BATCH_TABLE)) Capsule::schema()->create(self::BATCH_TABLE, static function($t) {
            $t->charset='utf8mb4'; $t->collation='utf8mb4_unicode_ci';
            $t->char('id',64)->primary(); $t->longText('payload'); $t->string('status',32);
            $t->timestamp('created_at')->useCurrent(); $t->timestamp('updated_at')->useCurrent();
            $t->index(['status','created_at'],'amsfb_batch_pending');
        });
    }

    public static function enabled(): bool
    {
        return self::checkpointEnabled() && (string)Database::getConfig('ai_queue_consolidation','0')==='1';
    }

    public static function checkpointEnabled(): bool
    {
        return (int)Database::getConfig('schema_version','0')>=23;
    }

    private static function readyQuery(int $now)
    {
        $query=Capsule::table('mod_amssoft_fail2ban_rollups')
            ->whereColumn('revision','>','analyzed_revision')->where('processing_state','!=','review')
            ->whereNull('blocked_confirmed_at')
            ->where('bucket','>=',date('Y-m-d H:i:s',$now-Policy::number('ai_behavior_hours')*3600))
            ->where('bucket','<=',date('Y-m-d H:i:s',$now))
            ->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s',$now)));
        return RecentActivity::query($query);
    }

    /** Read-only subject lower bound, NOT signature segments or API capacity. */
    public static function health(): array
    {
        if (!self::checkpointEnabled()) return ['unique_ready'=>0,'unique_subjects_ready'=>0,'pending_batches'=>0];
        $subjects=self::readyQuery(time())->select(['ip','source_log','pattern'])->distinct();
        $count=(int)Capsule::connection()->query()->fromSub($subjects,'ready_subjects')->count();
        return ['unique_ready'=>$count,'unique_subjects_ready'=>$count,
            'pending_batches'=>(int)Capsule::table(self::BATCH_TABLE)->where('status','pending')->count()];
    }

    public static function consolidate(array $batch): array
    {
        if (!self::enabled()) return $batch;
        $now=time(); $cutoff=$now-Policy::number('ai_behavior_hours')*3600;
        $result=[]; $used=[];
        foreach ($batch as $value) {
            $row=(array)$value;
            if (isset($used[$row['id']])) continue;
            if(!self::readyQuery($now)->where('id',$row['id'])->where('revision',$row['revision'])->exists())continue;
            $candidates=self::readyQuery($now)->where('ip',$row['ip'])->where('source_log',$row['source_log'])
                ->where('pattern',$row['pattern'])->where('id','!=',$row['id'])
                ->orderBy('bucket')->orderBy('id')->limit(self::MAX_ROWS-1)->get();
            $available=[];
            foreach ($candidates as $candidate) {
                $candidate=(array)$candidate;
                if (!isset($used[$candidate['id']])) $available[]=$candidate;
            }
            $group=self::consolidateRows([$row],$available,$now,$cutoff)[0];
            $group=ApplicationWindow::attach($group);
            $key=self::workKey($group);
            $group['_work_key']=$key;
            foreach ($group['_work_refs'] ?? [['id'=>$row['id'],'revision'=>$row['revision']]] as $ref) {
                $used[$ref['id']]=true;
                Capsule::table(self::TABLE)->insertOrIgnore(['key'=>$key,'rollup_id'=>$ref['id'],
                    'revision'=>$ref['revision'],'result_state'=>'pending','created_at'=>date('Y-m-d H:i:s',$now)]);
            }
            $result[]=$group;
        }
        return $result;
    }

    /** Pure partitioning. Extra candidates not selected remain pending in storage.
     * _work_refs are id/revision pairs; _work_snapshots contain untouched originals.
     * No proofEvents() expansion: every selected sample must fit in its entirety.
     */
    public static function consolidateRows(array $batch,array $candidates=[],?int $now=null,?int $cutoff=null): array
    {
        $now=$now ?? time(); $cutoff=$cutoff ?? $now-86400;
        $result=[]; $used=[]; $pool=array_merge($batch,$candidates);
        foreach ($batch as $value) {
            $row=(array)$value;
            if (isset($used[$row['id']])) continue;
            $original=$row; $used[$row['id']]=true;
            $events=self::events($row,$now,$cutoff);
            $signature=$events!==null ? self::signature($row) : null;
            $row['_work_refs']=[['id'=>$row['id'],'revision'=>(int)$row['revision']]];
            $row['_work_snapshots']=[$original];
            if ($events!==null) $row['_work_events']=$events;
            if ($signature===null || !self::ready($row,$now,$cutoff)) { $result[]=$row; continue; }
            $scanned=1;
            foreach ($pool as $value) {
                $candidate=(array)$value;
                if (($candidate['id']??null)===$original['id']) continue;
                if ($scanned++>=self::MAX_ROWS) break;
                if (isset($used[$candidate['id']]) || !self::ready($candidate,$now,$cutoff)
                    || $candidate['ip']!==$original['ip'] || $candidate['source_log']!==$original['source_log']
                    || $candidate['pattern']!==$original['pattern']) continue;
                $extra=self::events($candidate,$now,$cutoff);
                if ($extra===null || self::signature($candidate)!==$signature) continue;
                $combined=self::unionEvents($events,$extra);
                if ($combined===null || !self::fits($combined)) continue;
                $events=$combined; $used[$candidate['id']]=true;
                $row['_work_refs'][]=['id'=>$candidate['id'],'revision'=>(int)$candidate['revision']];
                $row['_work_snapshots'][]=$candidate;
                $row['events']=(int)$row['events']+(int)$candidate['events'];
            }
            $row['_work_events']=$events;
            $result[]=$row;
        }
        return $result;
    }

    private static function signature(array $row): ?string
    {
        if(PhpScan::grouped($row['pattern']??''))return 'php-scan:'.$row['pattern'];
        if(ProbeApplications::grouped($row['pattern']??''))return 'application-probe:'.$row['pattern'];
        if (!class_exists(DecisionMemory::class)) return null;
        return DecisionMemory::signature($row);
    }

    private static function ready(array $row,int $now,int $cutoff): bool
    {
        $bucket=strtotime($row['bucket']??'') ?: 0;
        $retry=empty($row['retry_at']) ? 0 : (strtotime($row['retry_at']) ?: PHP_INT_MAX);
        return (int)($row['revision']??0)>(int)($row['analyzed_revision']??0)
            && !in_array($row['processing_state']??'',['review','rejected'],true)
            && ($row['decision_state']??null)!=='rejected' && empty($row['blocked_confirmed_at'])
            && $retry<=$now && $bucket>=$cutoff && $bucket<=$now;
    }

    private static function events(array $row,int $now,int $cutoff): ?array
    {
        $applications=ProbeApplications::grouped($row['pattern']??'');
        $phpScan=PhpScan::grouped($row['pattern']??'');
        if($phpScan)$cutoff=max($cutoff,RecentActivity::cutoff(),$now-Policy::number('ai_php_scan_window_minutes')*60);
        if($applications)$cutoff=max($cutoff,RecentActivity::cutoff(),$now-Policy::number('ai_application_probe_window_minutes')*60);
        $events=$row['samples']??null;
        if (is_string($events)) $events=json_decode($events,true);
        if (!is_array($events) || !array_is_list($events) || !$events || !self::fits($events)) return null;
        $variants=[]; $ids=[];
        foreach ($events as $event) {
            if (!is_array($event) || !is_string($event['id']??null) || isset($ids[$event['id']])
                || ($event['ip']??null)!==$row['ip'] || ($event['pattern']??null)!==$row['pattern']
                || (isset($event['source_log']) && $event['source_log']!==$row['source_log'])
                || !is_string($event['line']??null) || !empty($event['truncated'])
                || ($event['time']??0)<$cutoff || ($event['time']??PHP_INT_MAX)>$now) return null;
            $ids[$event['id']]=true;
            if (method_exists(DecisionMemory::class,'lineSignature')) {
                $variant=$phpScan?PhpScan::signature($event['line'],$row['ip']):($applications?ProbeApplications::signature($event['line'],$row['ip']):DecisionMemory::lineSignature($event['line'],$row['ip']));
                if(($applications||$phpScan)&&BehaviorStore::eventTime($event['line'])!==$event['time'])return null;
                if ($variant===null) return null;
                $variants[$variant]=true;
            }
        }
        if (($row['behavior_variants']??null)!==null) {
            $stored=$row['behavior_variants'];
            if (is_string($stored)) $stored=json_decode($stored,true);
            if (empty($row['behavior_complete']) || !is_array($stored) || !array_is_list($stored) || !$stored
                || !method_exists(DecisionMemory::class,'lineSignature')) return null;
            $actual=array_keys($variants); $stored=array_values(array_unique($stored));
            sort($actual,SORT_STRING); sort($stored,SORT_STRING);
            if ($actual!==$stored) return null;
        } elseif ((int)($row['events']??0)!==count($events)) return null;
        return $events;
    }

    private static function fits(array $events): bool
    {
        if (count($events)>self::MAX_EVENTS) return false;
        $bytes=0;
        foreach ($events as $event) {
            if (!is_array($event) || !is_string($event['line']??null)) return false;
            $bytes+=strlen($event['line']);
        }
        return $bytes<=self::MAX_BYTES;
    }

    private static function unionEvents(array $events,array $extra): ?array
    {
        $byId=[];
        foreach (array_merge($events,$extra) as $event) {
            if (isset($byId[$event['id']]) && $byId[$event['id']]!==$event) return null;
            $byId[$event['id']]=$event;
        }
        return array_values($byId);
    }

    private static function workKey(array $row): string
    {
        return hash('sha256',json_encode([$row['id'],(int)$row['revision'],$row['campaign_signature']??null,
            array_map(fn($snapshot)=>[$snapshot['id'],$snapshot['revision'],$snapshot['campaign_signature']??null],$row['_work_snapshots']??[$row]),
            $row['_work_refs']??[],$row['_work_window_refs']??[],
            array_column($row['_work_events']??[],'id'),self::policyFingerprint()],JSON_THROW_ON_ERROR));
    }

    /** Nonmanual only, after a valid per-IP decision. Never acknowledges a newer revision. */
    public static function finalize(array $row,string $state='api'): void
    {
        if (!self::checkpointEnabled()) { BehaviorStore::acknowledge($row); return; }
        if (!preg_match('/\A[a-z][a-z0-9_]{0,31}\z/D',$state) || $state==='pending')
            throw new \InvalidArgumentException('Invalid analysis result state.');
        $snapshots=$row['_work_snapshots']??[$row];
        $refs=$row['_work_refs']??[['id'=>$row['id'],'revision'=>$row['revision']]];
        $originals=[];
        foreach ($snapshots as $snapshot) { $snapshot=(array)$snapshot; $originals[$snapshot['id']]=$snapshot; }
        Capsule::connection()->transaction(function()use($row,$refs,$originals,$state) {
            $key=$row['_work_key']??self::workKey($row); $now=time();
            foreach ($refs as $ref) {
                $ref=(array)$ref; $snapshot=$originals[$ref['id']]??null;
                if (!$snapshot || (int)$snapshot['revision']!==(int)$ref['revision']) continue;
                $live=Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$ref['id'])->lockForUpdate()->first();
                if (!$live || (int)$live->revision!==(int)$ref['revision']) continue;
                $live=(array)$live;
                if (!self::ready($live,$now,$now-Policy::number('ai_behavior_hours')*3600)) continue;
                foreach (['ip','source_log','pattern','processing_state','retry_at','attempts','validation_attempts','failure_code','decision_state'] as $field)
                    if (($live[$field]??null)!=($snapshot[$field]??null)) continue 2;
                $analysisKey=hash('sha256',$snapshot['id']."\0".$snapshot['revision']."\0".($snapshot['campaign_signature']??''));
                if (Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('task_id',$ref['id'])->where('analysis_key',$analysisKey)
                    ->where('status','rejected')->exists()) continue;
                BehaviorStore::acknowledge($snapshot);
                Capsule::table(self::TABLE)->insertOrIgnore(['key'=>$key,'rollup_id'=>$ref['id'],
                    'revision'=>$ref['revision'],'result_state'=>'pending','created_at'=>date('Y-m-d H:i:s',$now)]);
                // All reservations for this exact revision share the terminal result.
                Capsule::table(self::TABLE)->where('rollup_id',$ref['id'])->where('revision',$ref['revision'])
                    ->where('key',$key)
                    ->where('result_state','pending')->update(['result_state'=>$state]);
            }
        });
    }

    private static function policyFingerprint(): string
    {
        return DecisionMemory::policyFingerprint();
    }

    private static function encode(array $payload): string
    {
        $json=json_encode($payload,JSON_THROW_ON_ERROR);
        if (strlen($json)>self::MAX_PAYLOAD) throw new \LengthException('Analysis checkpoint exceeds 2 MiB.');
        return $json;
    }

    /** raw is the parsed subject response ONLY, never a transport body or config. */
    public static function saveBatch(array $batch,array $proofs,array $contexts,array $raw): string
    {
        if (!self::checkpointEnabled()) throw new \LogicException('Analysis checkpoints require schema 23.');
        $payload=self::encode(['batch'=>$batch,'proofs'=>$proofs,'contexts'=>$contexts,'raw'=>$raw,
            'done'=>[],'policy_hash'=>self::policyFingerprint()]);
        $id=bin2hex(random_bytes(32)); $now=date('Y-m-d H:i:s');
        Capsule::table(self::BATCH_TABLE)->insert(['id'=>$id,'payload'=>$payload,'status'=>'pending','created_at'=>$now,'updated_at'=>$now]);
        return $id;
    }

    /** Bounded drain; invalidated checkpoints remain visible, tasks remain untouched. */
    public static function nextBatch(): ?array
    {
        if (!self::checkpointEnabled()) return null;
        for ($scan=0;$scan<self::MAX_ROWS;$scan++) {
            $next=Capsule::connection()->transaction(function() {
                $record=Capsule::table(self::BATCH_TABLE)->where('status','pending')->orderBy('created_at')->orderBy('id')->lockForUpdate()->first();
                if (!$record) return null;
                $payload=json_decode($record->payload,true);
                $valid=is_array($payload) && strlen($record->payload)<=self::MAX_PAYLOAD
                    && ($payload['policy_hash']??null)===self::policyFingerprint()
                    && (strtotime($record->created_at)?:0)>time()-self::CHECKPOINT_TTL;
                foreach (['batch','proofs','contexts','raw','done'] as $field)
                    $valid=$valid && is_array($payload[$field]??null);
                if (!$valid) {
                    Capsule::table(self::BATCH_TABLE)->where('id',$record->id)->update(['status'=>'invalidated','updated_at'=>date('Y-m-d H:i:s')]);
                    return false;
                }
                $batch=array_values(array_filter($payload['batch'],fn($row)=>!isset($payload['done'][$row['id']])));
                if (!$batch) {
                    Capsule::table(self::BATCH_TABLE)->where('id',$record->id)->update(['status'=>'complete','updated_at'=>date('Y-m-d H:i:s')]);
                    return false;
                }
                return ['id'=>$record->id,'batch'=>$batch,'proofs'=>$payload['proofs'],
                    'contexts'=>$payload['contexts'],'raw'=>$payload['raw'],'done'=>$payload['done']];
            });
            if ($next!==false) return $next;
        }
        // Never authorize new API work merely because the drain bound was hit.
        if (Capsule::table(self::BATCH_TABLE)->where('status','pending')->exists())
            throw new \RuntimeException('Pending checkpoint drain limit reached.');
        return null;
    }

    public static function markItem(string $id,string $rollupId): void
    {
        self::updateCompletion($id,$rollupId);
    }

    public static function completeBatch(string $id): void
    {
        self::updateCompletion($id,null);
    }

    /** Bounded retention of terminal scheduling artifacts only. */
    public static function prune(): void
    {
        if (!self::checkpointEnabled()) return;
        $cutoff=date('Y-m-d H:i:s',time()-Policy::number('ai_evidence_retention_days')*86400);
        Capsule::table(self::BATCH_TABLE)->whereIn('status',['complete','invalidated'])
            ->where('created_at','<',$cutoff)->orderBy('created_at')->limit(self::MAX_ROWS)->delete();
        Capsule::table(self::TABLE)->where('result_state','!=','pending')
            ->where('created_at','<',$cutoff)->orderBy('created_at')->limit(self::MAX_ROWS)->delete();
    }

    private static function updateCompletion(string $id,?string $rollupId): void
    {
        if (!self::checkpointEnabled()) return;
        Capsule::connection()->transaction(function()use($id,$rollupId) {
            $record=Capsule::table(self::BATCH_TABLE)->where('id',$id)->lockForUpdate()->first();
            if (!$record || $record->status!=='pending') return;
            $payload=json_decode($record->payload,true,512,JSON_THROW_ON_ERROR);
            $ids=array_column($payload['batch'],'id');
            if ($rollupId!==null) {
                if (!in_array($rollupId,$ids,true)) throw new \InvalidArgumentException('Item does not belong to checkpoint.');
                $payload['done'][$rollupId]=true;
            }
            $complete=true;
            foreach ($ids as $item) if (!isset($payload['done'][$item])) { $complete=false; break; }
            Capsule::table(self::BATCH_TABLE)->where('id',$id)->update(['payload'=>self::encode($payload),
                'status'=>$complete?'complete':'pending','updated_at'=>date('Y-m-d H:i:s')]);
        });
    }
}
