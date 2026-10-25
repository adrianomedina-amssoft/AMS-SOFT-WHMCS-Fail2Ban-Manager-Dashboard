<?php
namespace AMS\Fail2Ban;

/** Pure presentation helpers. No SQL, provider or native mutations. */
final class ProtectionView
{
    public static function count($value): string
    {
        return (is_int($value)&&$value>=0)||(is_string($value)&&preg_match('/^(?:0|[1-9][0-9]{0,18})$/D',$value))
            ?(string)$value:'não medido';
    }

    private static function timestamp($value,int $now): ?int
    {
        if(self::count($value)==='não medido')return null;
        $time=(int)$value;return $time>0&&$time<=$now?$time:null;
    }

    public static function states(array $values,array $health,int $lastRun,int $now): array
    {
        $stale=max(1,(int)$values['ai_stale_minutes'])*60;
        $collector=self::timestamp($health['collector']??null,$now);
        $collectorOk=$collector!==null&&$now-$collector<$stale&&empty($health['collector_error']);
        $states=['collector'=>['tone'=>$collectorOk?'success':'warning','label'=>$collectorOk?'Atualizada':'Atenção à coleta'],
            'jail'=>['tone'=>!empty($health['jail']['success'])?'success':'warning','label'=>!empty($health['jail']['success'])?'Configuração conferida':'Não confirmada']];
        $cycle=$health['telemetry']['state']??[];
        $heartbeat=self::timestamp($health['cycle']??$lastRun,$now);
        $started=self::timestamp($cycle['started_at']??null,$now);
        if(($values['ai_auto_enabled']??'0')!=='1')$states['ai']=['tone'=>'default','label'=>'Desativada'];
        elseif(!empty($health['error'])||($cycle['status']??'')==='error')$states['ai']=['tone'=>'danger','label'=>'Falha registrada'];
        elseif($heartbeat===null||(($cycle['status']??'')==='running'&&$started===null))$states['ai']=['tone'=>'warning','label'=>'Horário do ciclo não confirmado'];
        elseif(($cycle['status']??'')==='running'&&$now-$started<=(int)$values['ai_cycle_seconds']+60)$states['ai']=['tone'=>'info','label'=>'Em análise'];
        elseif(($cycle['status']??'')==='running'||$now-$heartbeat>=$stale)$states['ai']=['tone'=>'warning','label'=>'Ciclo atrasado ou não confirmado'];
        else $states['ai']=['tone'=>'success','label'=>'Ciclo atualizado'];
        $queue=$health['queue']??[];
        $urgent=!empty($queue['age_alert'])||!empty($queue['expiry']['warning']);
        $ready=self::count($queue['ready']??null);
        $states['queue']=$urgent?['tone'=>'warning','label'=>'Atenção ao prazo']:
            ($ready==='não medido'?['tone'=>'warning','label'=>'Fila não medida']:
                ['tone'=>'info','label'=>(int)$ready>0?'Trabalho pronto':'Sem trabalho pronto']);
        return $states;
    }

    public static function code(string $code): string
    {
        return match($code){
            'filter_positive'=>'A regra não reconheceu a prova exigida',
            'filter_identity'=>'Identidade da regra não validada',
            'filter_peer'=>'Captura do IP de origem recusada',
            'filter_branch'=>'Ramo da regra sem prova suficiente',
            'filter_legitimate'=>'A regra atingiu tráfego legítimo',
            'update_cooldown'=>'Intervalo mínimo entre ampliações',
            'daily_limit'=>'Quota diária atingida',
            'managed_limit'=>'Teto de jails gerenciadas atingido',
            'promotion_threshold'=>'Aguardando critérios para aprendizado',
            'time_limit'=>'Ciclo encerrado pelo orçamento seguro',
            'call_limit'=>'Limite de chamadas do ciclo atingido',
            'queue_not_ready'=>'Sem mais trabalho pronto neste ciclo',
            'local_work_completed'=>'Trabalho concluído localmente, sem nova chamada',
            'coverage_unavailable'=>'Cobertura local não confirmada',
            'completed'=>'Concluído', 'monitoring'=>'Acompanhando', 'queued'=>'Enfileirado',
            'running'=>'Em execução', 'failed'=>'Falhou', 'error'=>'Erro',
            ''=>'Sem diagnóstico', default=>$code,
        };
    }
}
