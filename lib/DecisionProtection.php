<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/RecentActivity.php';
use WHMCS\Database\Capsule;

/** Shared observation only: no ban, unban, acknowledgement or paid request. */
final class DecisionProtection
{
    public const TABLE='mod_amssoft_fail2ban_decision_state';
    public const VIEWS=['actionable','waiting','protected','checking','review','history'];
    private static ?array $projection=null;

    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=24;}
    public static function migrate(): void
    {
        if(Capsule::schema()->hasTable(self::TABLE))return;
        Capsule::schema()->create(self::TABLE,function($t){
            $t->unsignedBigInteger('suggestion_id')->primary();$t->string('state',24);$t->string('view',24)->index();
            $t->string('service',16);$t->string('reason',80);$t->longText('proof');$t->char('snapshot_id',64);
            $t->timestamp('observed_at');$t->timestamp('valid_until')->index();
        });
    }
    public static function snapshot(array $ips=[]): array
    {
        $ips=array_values(array_unique(array_filter(array_map(fn($ip)=>Safety::canonicalIp($ip),$ips))));
        $args=['protection-snapshot'];if(count($ips)<=10)$args=array_merge($args,$ips);
        try{$s=Privileged::run($args);}catch(CycleBudgetExceeded $e){throw $e;}
        catch(\Throwable $e){$s=['success'=>false,'reason'=>'coverage_unavailable'];}
        $s['ttl']=Policy::number('ai_blocked_recheck_seconds');return $s;
    }
    public static function lines(array $row): array
    {
        if(isset($row['_work_events']))return array_column($row['_work_events'],'line');
        $value=$row['samples']??$row['evidence']??[];
        if(is_string($value))$value=json_decode($value,true)?:[];
        $lines=[];foreach(is_array($value)?$value:[] as $entry){$line=is_array($entry)?($entry['line']??null):$entry;if(is_string($line))$lines[]=$line;}return $lines;
    }
    public static function service(array $row): string
    {
        $source=$row['source_log']??null;
        if($source!==null&&$source!==''){
            if($source==='/var/log/whmcs_auth.log'||in_array($source,array_filter(LogSources::APPROVED,fn($p)=>str_starts_with($p,'/var/log/apache2/')),true))return 'http';
            if($source==='/var/log/auth.log')return 'ssh';
            return 'unknown';
        }
        $lines=self::lines($row);if(!$lines)return 'unknown';$services=[];
        foreach($lines as $line){
            if(Safety::sourceIp($line)!==Safety::canonicalIp($row['ip']??''))return 'unknown';
            // Apache also logs empty/malformed requests ("-", TLS bytes,
            // unusual verbs). Infer the service from the peer/date/status
            // envelope, not from whether the request uses a familiar method.
            $access=preg_match('~^\S+\s+-\s+\S+\s+\[[^\]\r\n]+\]\s+"[^\r\n]*"\s+\d{3}\s+(?:\d+|-)(?:\s|$)~',$line);
            if($access||BlockedTasks::httpRow(['ip'=>$row['ip'],'samples'=>json_encode([['line'=>$line]])])||preg_match('/ WHMCS login failed from /',$line))$services['http']=true;
            elseif(preg_match('/sshd(?:\[\d+\])?:/',$line))$services['ssh']=true;
            else return 'unknown';
        }
        return count($services)===1?array_key_first($services):'unknown';
    }
    public static function classify(array $row,array $snapshot): array
    {
        $now=time();$service=self::service($row);$unknown=['state'=>'unknown','service'=>$service,'reason'=>'coverage_unavailable','proof'=>null,'valid_until'=>$now];
        $ip=Safety::canonicalIp($row['ip']??'');
        if(!$ip||$service==='unknown')return array_replace($unknown,['state'=>'not_applicable','reason'=>'service_unknown']);
        $observed=$snapshot['observed_at']??null;$ttl=$snapshot['ttl']??0;
        if(($snapshot['success']??false)!==true||($snapshot['stable']??false)!==true||!empty($snapshot['errors'])
            ||!is_int($observed)||$observed>$now||$observed+$ttl<=$now)return $unknown;
        $ports=$snapshot['requirements'][$service]??[];
        if(!$ports||!is_array($ports)||array_filter($ports,fn($p)=>!is_int($p)||$p<1||$p>65535))return array_replace($unknown,['reason'=>'service_ports_unknown']);
        $covered=[];
        foreach($snapshot['entries']??[] as $e){
            if(($e['ip']??null)!==$ip||($e['effective']??false)!==true||($e['protocol']??null)!=='tcp')continue;
            $until=min($observed+$ttl,($e['expires_at']??PHP_INT_MAX)-1);if($until<=$now)continue;
            foreach($ports as $port)if(in_array($port,$e['ports']??[],true)&&$until>($covered[$port]['until']??0))
                $covered[$port]=['jail'=>$e['jail'],'ticket_id'=>hash('sha256',$e['ticket']),'port'=>$port,'until'=>$until];
        }
        if(count($covered)!==count(array_unique($ports)))return ['state'=>'unprotected','service'=>$service,'reason'=>'no_effective_coverage','proof'=>null,'valid_until'=>$observed+$ttl];
        return ['state'=>'protected','service'=>$service,'reason'=>'effective_coverage','proof'=>['observed_at'=>$observed,'coverage'=>array_values($covered)],'valid_until'=>min(array_column($covered,'until'))];
    }
    public static function filterLines(array $lines): array
    {
        if(RecentActivity::enabled())$lines=RecentActivity::filterLines($lines);
        $ips=[];foreach($lines as $line)if(is_string($line)&&($ip=Safety::sourceIp($line)))$ips[]=$ip;
        if(!$ips)return [];
        $snapshot=self::snapshot($ips);$result=[];
        foreach($lines as $line){if(!is_string($line)||!($ip=Safety::sourceIp($line)))continue;
            $state=self::classify(['ip'=>$ip,'evidence'=>[$line]],$snapshot);
            if(in_array($state['state'],['unknown','not_applicable'],true))throw new ProtectionUnavailable('Consulta local da proteção indisponível; API não autorizada.');
            if($state['state']==='unprotected')$result[]=$line;
        }return $result;
    }
    public static function assertLines(array $lines): void
    {
        if(count(self::filterLines($lines))!==count($lines))throw new ProtectedBatchChanged('Proteção mudou; reconstruir lote antes de enviar à API.');
    }
    public static function guardRows(array $rows,bool $requireKnown=false): array
    {
        if(!$rows)return [];$s=self::snapshot(array_column($rows,'ip'));$out=[];
        foreach($rows as $r){$state=self::classify($r,$s);
            if(in_array($state['state'],['unknown','not_applicable'],true)){
                if($requireKnown){
                    // Keep the checkpoint's CAS fields identical. The saved
                    // response is retried locally next cycle, never resent.
                    Database::setConfig('ai_last_error','Consulta local da proteção indisponível; resposta salva aguarda rechecagem sem API.');
                    throw new ProtectionUnavailable('Retomada local aguarda confirmação da proteção; resposta salva preservada.');
                }
                // Local retry, not a provider attempt or a claim of protection.
                Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r['id'])->where('revision',$r['revision'])
                    ->where('processing_state','!=','review')->where(fn($q)=>$q->whereNull('retry_at')->orWhere('retry_at','<=',date('Y-m-d H:i:s')))
                    ->update(['retry_at'=>date('Y-m-d H:i:s',time()+min(300,Policy::number('ai_blocked_recheck_seconds'))),
                        'failure_code'=>'coverage_unavailable','failure_detail'=>'Rechecagem local pendente; nenhuma chamada de IA autorizada.']);
                Database::setConfig('ai_last_error','Consulta local da proteção indisponível; tarefas aguardam rechecagem sem API.');
                continue;
            }
            if($state['state']==='unprotected'){$out[]=$r;continue;}
            Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r['id'])->where('revision',$r['revision'])
                ->update(['blocked_confirmed_at'=>date('Y-m-d H:i:s',$s['observed_at']),'blocked_until_check_at'=>date('Y-m-d H:i:s',$state['valid_until']),'blocked_by_json'=>json_encode($state['proof'])]);
        }return $out;
    }
    public static function refresh(?array $snapshot=null,bool $persist=true): array
    {
        $snapshot=$snapshot??self::snapshot();$now=time();$id=hash('sha256',json_encode($snapshot));
        $recent=RecentActivity::enabled();$policyHash=$recent?DecisionMemory::policyFingerprint():null;
        $groups=array_fill_keys(self::VIEWS,[]);$states=[];
        $rows=Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('status','pending')->where('classification','ban')->get();
        foreach($rows as $object){
            $r=(array)$object;$s=self::classify($r,$snapshot);
            if($recent)$s['eligibility']=DecisionEligibility::evaluate($r);
            $view=self::viewFor($r,$s);
            $s['view']=$view;$groups[$view][]=(int)$r['id'];$states[(int)$r['id']]=$s;
        }
        // Read-only presentation neither writes SQL nor seeds the worker's projection cache.
        if(!$persist)return ['groups'=>$groups,'states'=>$states,'observed_at'=>$snapshot['observed_at']??$now];
        // Projection is scheduling/UI metadata only; status/evidence never change.
        Capsule::connection()->transaction(function()use($states,$snapshot,$now,$id,$recent,$policyHash){
            foreach($states as $key=>$s)Capsule::table(self::TABLE)->updateOrInsert(['suggestion_id'=>$key],[
                'state'=>$s['state'],'view'=>$s['view'],'service'=>$s['service'],'reason'=>$s['reason'],'proof'=>json_encode($s['proof']),
                'snapshot_id'=>$id,'observed_at'=>date('Y-m-d H:i:s',$snapshot['observed_at']??$now),'valid_until'=>date('Y-m-d H:i:s',max($now,$s['valid_until']))]
                +($recent?['eligibility_reason'=>$s['eligibility']['reason'],
                    'evidence_latest_at'=>$s['eligibility']['latest']?date('Y-m-d H:i:s',$s['eligibility']['latest']):null,'policy_hash'=>$policyHash]:[]));
        });
        return self::$projection=['groups'=>$groups,'states'=>$states,'observed_at'=>$snapshot['observed_at']??$now];
    }
    public static function viewFor(array $r,array $s): string
    {
        if($s['state']==='protected')return 'protected';
        if(in_array($s['state'],['unknown','not_applicable'],true))return 'checking';
        if(RecentActivity::enabled())return ($s['eligibility']??DecisionEligibility::evaluate($r))['view'];
        $latest=0;foreach(self::lines($r) as $line){$t=BehaviorStore::eventTime($line)??0;if($t<=time()+300)$latest=max($latest,$t);}
        $fresh=$latest>=time()-Policy::number('ai_behavior_hours')*3600;
        if(!$fresh)$fresh=Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$r['ip'])->where('source_log',$r['source_log'])
            ->where('pattern',$r['pattern'])->where('bucket','>=',date('Y-m-d H:i:s',time()-Policy::number('ai_behavior_hours')*3600))->whereColumn('revision','>','analyzed_revision')->exists();
        if(!$fresh)return 'history';
        $quarantine=json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[];
        if(in_array($r['decision_code']??'',['filter_positive','filter_identity','filter_peer','filter_branch','filter_legitimate','no_eligible_proof','manual_review','confidence_low'],true)
            ||in_array('amsfb-'.Safety::filterName($r['filter_name']??''),$quarantine,true))return 'review';
        return 'actionable';
    }
    public static function ids(string $view='actionable'): array {return (self::$projection??self::refresh())['groups'][$view]??[];}
    public static function projection(): array {return self::$projection??self::refresh();}
    public static function reset(): void {self::$projection=null;}
}
