<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Persistent, one-shot work. HTTP can preview/queue, never unban/delete. */
final class Maintenance
{
    private const TABLES=['logs'=>'id','ai_suggestions'=>'id','detections'=>'fingerprint','rollups'=>'id'];
    private const MAX_RECORDS=10000;
    private const MAX_PAYLOAD_BYTES=1048576;

    public static function recent(): array
    {
        if(!Capsule::schema()->hasTable('mod_amssoft_fail2ban_jobs')) return [];
        return Capsule::table('mod_amssoft_fail2ban_jobs')->where('status','!=','preview')
            ->select(['id','admin_id','status','created_at','updated_at','result'])
            ->orderByDesc('created_at')->limit(20)->get()->map(function($row){
                $r=(array)$row;$result=json_decode($r['result']??'',true)?:[];
                $archives=$result['archives']??[];
                $summary=array_intersect_key($result,array_flip(['backup_complete','backup_reverified','recovered_errors','cleaned','deleted','target_index','unbanned','skipped_new_or_expired','policy_resumed','error','monitor']));
                if(isset($summary['monitor'])&&is_array($summary['monitor'])){
                    $monitor=$summary['monitor'];
                    $summary['monitor']=array_intersect_key($monitor,array_flip(['success','active','completed','samples','errors','coverage_samples','coverage_versions_seen','max_missing_rules','max_orphan_rules','max_missing_jail_tickets','jails_without_actions_seen','jails_unverified_seen']));
                    foreach(['first','last'] as $edge){
                        $sample=$monitor[$edge]??null;
                        $summary['monitor'][$edge]=is_array($sample)?array_intersect_key($sample,array_flip(['timestamp','measurement_stable','coverage_version','active_jails','daemon_ban_entries','daemon_unique_ips','firewall_unique_ips','missing_f2b_rules','orphan_firewall_ips','missing_jail_tickets','error'])):null;
                    }
                }
                $summary['archive_parts']=count($archives);
                $summary['archive_bytes']=array_sum(array_column($archives,'bytes'));
                $summary['manifest_sha256']=$archives?hash('sha256',json_encode($archives)):null;
                $r['result']=json_encode($summary,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
                unset($r['payload']);return $r;
            })->all();
    }

    private static function rows(string $suffix,array $payload)
    {
        $q=Capsule::table('mod_amssoft_fail2ban_'.$suffix);
        $column=match($suffix){'logs'=>'timestamp','detections'=>'detected_at','rollups'=>'updated_at',default=>'created_at'};
        $q->where($column,'<=',$payload['cutoff']);
        if(isset($payload['record_ids'][$suffix])) $q->whereIn(self::TABLES[$suffix],$payload['record_ids'][$suffix]);
        if($suffix==='ai_suggestions') $q->where(fn($where)=>$where->whereNull('updated_at')->orWhere('updated_at','<',$payload['cutoff']));
        if(in_array($suffix,['logs','ai_suggestions'],true)) $q->where('id','<=',$payload['max_ids'][$suffix]??0);
        if($suffix==='logs') $q->where('action','!=','policy_changed')->where('action','not like','maintenance_%');
        return $q;
    }

    public static function preview(array $input,int $admin,Fail2BanClient $client): array
    {
        if($admin<1)throw new \InvalidArgumentException('Administrador inválido.');
        return self::buildPreview($input,$admin,$client);
    }

    /** Explicit OS-root entry point; actor 0 is never accepted by the web API. */
    public static function previewForRootCli(array $input,Fail2BanClient $client): array
    {
        self::requireRootCli();
        return self::buildPreview($input,0,$client);
    }

    private static function requireRootCli(): void
    {
        if(PHP_SAPI!=='cli'||!function_exists('posix_geteuid')||posix_geteuid()!==0)
            throw new \InvalidArgumentException('Operação exclusiva do terminal root.');
    }

    private static function buildPreview(array $input,int $admin,Fail2BanClient $client): array
    {
        foreach($input as $value)if(!is_string($value)||strlen($value)>16384)throw new \InvalidArgumentException('Parâmetro inválido ou excessivo.');
        $kind=$input['kind']??''; $scope=$input['scope']??'';
        if(!in_array($kind,['archive','unban','both','monitor'],true)||!in_array($scope,['ai','all','selected'],true))
            throw new \InvalidArgumentException('Operação/escopo inválido.');
        $archive=in_array($kind,['archive','both'],true);
        if(!in_array($kind,['unban','both'],true))$scope='ai';
        if(!$client->ping()) throw new \InvalidArgumentException('Fail2Ban indisponível; não é seguro congelar os alvos.');
        $jails=$client->getJails();
        if($scope==='ai') $jails=array_values(array_filter($jails,fn($j)=>$j==='ai-bans'||str_starts_with($j,'amsfb-')));
        elseif($scope==='selected') {
            $selected=array_values(array_unique(array_filter(array_map('trim',explode(',',$input['jails']??'')))));
            if(!$selected||array_diff($selected,$jails)) throw new \InvalidArgumentException('Selecione jails ativas válidas.');
            $jails=$selected;
        }
        $targets=[];
        if(in_array($kind,['unban','both'],true)&&$jails) {
            $result=Privileged::run(array_merge(['tickets'],$jails));
            if(empty($result['success'])||!is_array($result['targets']??null)) throw new \InvalidArgumentException('Não foi possível obter a identidade temporal dos bans.');
            $targets=$result['targets'];
            if(count($targets)>self::MAX_RECORDS)throw new \InvalidArgumentException('Prévia excede 10.000 tickets; reduza o escopo de jails.');
        }
        $id=bin2hex(random_bytes(16));
        $cutoff=time();
        if($archive&&!empty($input['cutoff'])) {
            $parsed=\DateTimeImmutable::createFromFormat('!Y-m-d\TH:i',$input['cutoff']);
            if(!$parsed||$parsed->format('Y-m-d\TH:i')!==$input['cutoff']||$parsed->getTimestamp()>time())
                throw new \InvalidArgumentException('Data de corte inválida ou futura.');
            $cutoff=$parsed->getTimestamp();
        }
        foreach(['clear_logs','clear_suggestions','clear_observations','monitor'] as $flag)
            if(isset($input[$flag])&&!in_array($input[$flag],['0','1'],true))throw new \InvalidArgumentException('Opção de manutenção inválida.');
        $selected=['logs'=>$archive&&($input['clear_logs']??'1')==='1','ai_suggestions'=>$archive&&($input['clear_suggestions']??'1')==='1',
            'detections'=>$archive&&($input['clear_observations']??'1')==='1','rollups'=>$archive&&($input['clear_observations']??'1')==='1'];
        if(in_array($kind,['archive','both'],true)&&$selected['ai_suggestions']&&!$selected['detections'])
            throw new \InvalidArgumentException('Limpar sugestões exige arquivar também suas observações vinculadas.');
        $payload=['kind'=>$kind,'scope'=>$scope,'jails'=>$jails,'targets'=>$targets,'cutoff'=>date('Y-m-d H:i:s',$cutoff),
            'version'=>Database::getConfig('policy_version','0'),'expires'=>time()+300,
            'monitor'=>$kind==='monitor'||($input['monitor']??'0')==='1',
            'hours'=>Policy::number('monitor_hours'),'interval'=>Policy::number('monitor_interval'),
            'max_ids'=>[]];
        foreach(['logs','ai_suggestions'] as $table) $payload['max_ids'][$table]=$selected[$table]?(int)Capsule::table('mod_amssoft_fail2ban_'.$table)->max('id'):0;
        $counts=[];$remaining=self::MAX_RECORDS;
        foreach(self::TABLES as $table=>$key) {
            $payload['record_ids'][$table]=$selected[$table]?self::rows($table,$payload)->limit($remaining+1)->pluck($key)->all():[];
            $counts[$table]=count($payload['record_ids'][$table]);
            $remaining-=$counts[$table];
            if($remaining<0)throw new \InvalidArgumentException('Prévia excede 10.000 registros; reduza a data de corte ou as tabelas selecionadas. Nada foi enfileirado.');
        }
        $payload['rollup_revisions']=$payload['record_ids']['rollups']?self::rows('rollups',$payload)->pluck('revision','id')->all():[];
        $encoded=json_encode($payload,JSON_THROW_ON_ERROR);
        if(strlen($encoded)>self::MAX_PAYLOAD_BYTES)throw new \InvalidArgumentException('Prévia excede 1 MiB; reduza a data de corte, tabelas ou escopo de jails. Nada foi enfileirado.');
        Capsule::table('mod_amssoft_fail2ban_jobs')->insert(['id'=>$id,'admin_id'=>$admin,'status'=>'preview','payload'=>$encoded]);
        return ['nonce'=>$id,'expires_in'=>300,'bans'=>count($targets),'targets'=>$targets,'records'=>$counts,
            'cutoff'=>$payload['cutoff'],'monitor_hours'=>$payload['monitor']?$payload['hours']:0,
            'notice'=>'Arquivo/limpeza abrange o histórico operacional do módulo. Escopo de jails se aplica aos desbloqueios. Configuração, chaves, whitelist, GeoIP e logs originais são preservados.'];
    }

    public static function queue(array $input,int $admin): array
    {
        if($admin<1)throw new \InvalidArgumentException('Administrador inválido.');
        return self::queueForActor($input,$admin);
    }

    public static function queueForRootCli(array $input): array
    {
        self::requireRootCli();
        return self::queueForActor($input,0);
    }

    private static function queueForActor(array $input,int $admin): array
    {
        if(!is_string($input['nonce']??null)||!preg_match('/^[a-f0-9]{32}$/D',$input['nonce']))throw new \InvalidArgumentException('Prévia inválida.');
        if(($input['confirmation']??'')!=='EXECUTAR MANUTENCAO') throw new \InvalidArgumentException('Frase de confirmação inválida.');
        return Capsule::connection()->transaction(function()use($input,$admin){
            $row=Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$input['nonce']??'')->where('admin_id',$admin)->lockForUpdate()->first();
            if(!$row) throw new \InvalidArgumentException('Prévia inexistente.');
            if($row->status!=='preview') return ['job'=>$row->id,'status'=>$row->status,'repeated'=>true];
            $p=json_decode($row->payload,true);
            if($p['expires']<=time()||$p['version']!==Database::getConfig('policy_version','0')) throw new \InvalidArgumentException('Prévia expirada ou política alterada. Gere outra.');
            Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$row->id)->update(['status'=>'queued','updated_at'=>date('Y-m-d H:i:s')]);
            Database::logEvent('','','maintenance_queued','Trabalho '.$row->id,$admin);
            return ['job'=>$row->id,'status'=>'queued'];
        });
    }

    private static function checkpoint(string $id,string $status,array $result): void
    {
        Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$id)->update([
            'status'=>$status,'result'=>json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE),'updated_at'=>date('Y-m-d H:i:s')]);
    }

    public static function retry(array $input,int $admin): array
    {
        if(($input['confirmation']??'')!=='EXECUTAR MANUTENCAO')throw new \InvalidArgumentException('Confirme a retomada com a frase exigida.');
        return Capsule::connection()->transaction(function()use($input,$admin){
            $job=Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$input['job']??'')->lockForUpdate()->first();
            if(!$job||$job->status!=='failed'||($admin!==0&&(int)$job->admin_id!==0&&(int)$job->admin_id!==$admin))throw new ProtectionFailure('retry_not_allowed');
            $p=json_decode($job->payload,true);$r=json_decode($job->result??'',true)?:[];
            if($p['version']!==Database::getConfig('policy_version','0') && empty($r['policy_resumed']))throw new ProtectionFailure('retry_policy_changed');
            if(empty($r['backup_complete']))throw new ProtectionFailure('retry_backup_incomplete');
            $tmp=tempnam('/tmp','amsfb_manifest_');if(!$tmp)throw new \RuntimeException('Manifesto temporário indisponível.');
            try {
                if(file_put_contents($tmp,json_encode($r['archives']??[]))===false)throw new \RuntimeException('Manifesto incompleto.');
                $verified=Privileged::run(['verify-archive',$job->id,$tmp]);
                if(empty($verified['success']))throw new ProtectionFailure('retry_archive_unverified');
            } finally {@unlink($tmp);}
            $r['recovered_errors'][]=$r['error']??'Falha anterior';unset($r['error']);
            $r['backup_reverified']=$verified['verified_parts'];
            self::checkpoint($job->id,'running',$r);
            Database::logEvent('','','maintenance_resumed','Retomado sem ampliar escopo: '.$job->id,$admin);
            return ['job'=>$job->id,'status'=>'running','verified_parts'=>$verified['verified_parts']];
        });
    }

    private static function archive(string $id,array $body,int $part): array
    {
        $tmp=tempnam('/tmp','amsfb_archive_');
        if($tmp===false) throw new \RuntimeException('Arquivo temporário indisponível.');
        try {
            $json=json_encode($body,JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);
            if(strlen($json)>2*1024*1024) throw new \RuntimeException('Lote de backup excedeu limite; nenhuma limpeza executada.');
            if(file_put_contents($tmp,$json)!==strlen($json)) throw new \RuntimeException('Backup temporário incompleto.');
            $r=Privileged::run(['archive-part',$id,(string)$part,$tmp]);
            if(empty($r['success'])) throw new \RuntimeException('Backup privado não validado.');
            return $r;
        } finally { @unlink($tmp); }
    }

    public static function tick(Fail2BanClient $client): void
    {
        $lock=Capsule::selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired");
        if((int)$lock->acquired!==1) return;
        try {
            $jobs=Capsule::table('mod_amssoft_fail2ban_jobs')->whereIn('status',['queued','running','monitoring'])->orderBy('created_at')->limit(5)->get();
            foreach($jobs as $job) {
                $p=json_decode($job->payload,true); $r=json_decode($job->result??'',true)?:[];
                try {
                    if($job->status!=='monitoring') {
                        if($job->status==='queued'&&$p['version']!==Database::getConfig('policy_version','0'))
                            throw new \RuntimeException('Política alterada após confirmação; gere nova prévia.');
                        self::checkpoint($job->id,'running',$r);
                        if(empty($r['backup_complete'])) {
                            // Stage every export before any deletion/unban. Fixed parts
                            // are content-address checked by the root-owned bridge.
                            $part=0; $r['archives']=[];
                            $r['archives'][]=self::archive($job->id,['payload'=>$p],$part++);
                            if(in_array($p['kind'],['archive','both'],true)) foreach(self::TABLES as $table=>$key) {
                                $after=null;
                                while(true) {
                                    $q=self::rows($table,$p)->orderBy($key)->limit($table==='rollups'?5:20);
                                    if($after!==null) $q->where($key,'>',$after);
                                    $rows=$q->get()->map(fn($v)=>(array)$v)->all();
                                    if(!$rows) break;
                                    $r['archives'][]=self::archive($job->id,['table'=>$table,'rows'=>$rows],$part++);
                                    $after=end($rows)[$key];
                                    if($part>9999) throw new \RuntimeException('Backup excedeu limite.');
                                }
                            }
                            $r['backup_complete']=true;
                            self::checkpoint($job->id,'running',$r);
                        }
                        if(empty($r['cleaned'])&&in_array($p['kind'],['archive','both'],true)) {
                            Capsule::connection()->transaction(function()use($p,&$r){
                                foreach(['detections','ai_suggestions','logs'] as $table) $r['deleted'][$table]=self::rows($table,$p)->delete();
                                $r['deleted']['rollups']=0;
                                foreach($p['rollup_revisions']??[] as $id=>$revision)
                                    $r['deleted']['rollups']+=self::rows('rollups',$p)->where('id',$id)->where('revision',$revision)->delete();
                                $r['cleaned']=true;
                            });
                            self::checkpoint($job->id,'running',$r);
                        }
                        $index=$r['target_index']??0; $started=microtime(true);
                        while($index<count($p['targets']) && microtime(true)-$started<30) {
                            $tmp=tempnam('/tmp','amsfb_targets_');if(!$tmp)throw new \RuntimeException('Lote temporário indisponível.');
                            try {
                                if(file_put_contents($tmp,json_encode(array_slice($p['targets'],$index,100)))===false)throw new \RuntimeException('Lote temporário incompleto.');
                                $result=Privileged::run(['unban-tickets',$tmp]);
                            } finally {@unlink($tmp);}
                            if(empty($result['success']))throw new \RuntimeException('Desbloqueio parcial; lote não confirmado.');
                            foreach($result['results']??[] as $ticket) {
                                $key=empty($ticket['skipped'])?'unbanned':'skipped_new_or_expired';
                                $r[$key]=($r[$key]??0)+1; $r['target_index']=++$index;
                            }
                            self::checkpoint($job->id,'running',$r);
                            if(!empty($result['error'])||empty($result['results']))throw new \RuntimeException('Desbloqueio parcial; confira os alvos restantes.');
                        }
                        if($index<count($p['targets'])) continue;
                        if(!empty($p['resume_policy'])&&empty($r['policy_resumed'])) {
                            Policy::save($p['resume_policy'],(int)$job->admin_id,$p['version']??null);
                            $r['policy_resumed']=true;
                            self::checkpoint($job->id,'running',$r);
                        }
                        if($p['monitor']) {
                            $m=Privileged::run(['monitor-start',$job->id,(string)$p['hours'],(string)$p['interval']]);
                            if(empty($m['success'])) throw new \RuntimeException('Monitor não iniciado.');
                            $r['monitor']=$m; self::checkpoint($job->id,'monitoring',$r);
                        } else {
                            self::checkpoint($job->id,'completed',$r);
                            Database::logEvent('','','maintenance_completed','Trabalho '.$job->id,(int)$job->admin_id);
                        }
                    } else {
                        $m=Privileged::run(['monitor-status',$job->id]);
                        if(empty($m['success'])) throw new \RuntimeException('Consulta do monitor falhou.');
                        $r['monitor']=$m;
                        $status=$m['active']?'monitoring':($m['completed']?'completed':'failed');
                        self::checkpoint($job->id,$status,$r);
                    }
                } catch(\Throwable $e) {
                    $r['error']=$e->getMessage(); self::checkpoint($job->id,'failed',$r);
                    Database::logEvent('','','maintenance_failed','Trabalho '.$job->id.': '.$e->getMessage(),(int)$job->admin_id);
                }
            }
        } finally { Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_cycle')"); }
    }
}
