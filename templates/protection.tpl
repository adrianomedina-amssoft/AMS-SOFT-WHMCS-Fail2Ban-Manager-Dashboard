<?php
$groups=array_values(array_unique(array_column($fields,0)));
$submittedValues=$submittedValues??$values;
$queue=$health['queue']??[];$blocked=$queue['blocked']??[];$telemetry=$health['telemetry']??[];$lastCycle=$telemetry['last']??[];
$states=\AMS\Fail2Ban\ProtectionView::states($values,$health,(int)$lastRun,time());
$code=fn($value)=>\AMS\Fail2Ban\ProtectionView::code((string)$value);
$count=fn($value)=>\AMS\Fail2Ban\ProtectionView::count($value);
$date=fn($value)=>$value?date('d/m/Y H:i:s',(int)$value):'não medido';
$reviewCounts=$reviewCounts??['recent'=>count($reviewTasks),'history'=>0];
$reviewView=$reviewView??'recent';$reviewPage=$reviewPage??1;$reviewPages=$reviewPages??1;
$queryTiming=\AMS\Fail2Ban\QueryProbe::timing($values);
?>
<link rel="stylesheet" href="<?= $e(($asset_base??\AMS\Fail2Ban\Helper::assetBase()).'css/protection.css?v=2.2.24') ?>">
<div id="amsfb-protection" data-endpoint="<?= $e($modulelink.'&action=protection') ?>" data-csrf="<?= $e($csrf_token) ?>">
<h2>Proteção e manutenção <small>Política <?= $e($version) ?></small></h2>
<p>Fail2Ban na primeira camada; IA complementar. IPs com cobertura efetiva confirmada não são enviados à IA.</p>
<nav class="amsfb-protection-links" aria-label="Seções de proteção"><a href="#protection-state">Estado atual</a><a href="#protection-settings">Configurações</a><a href="#protection-diagnostics">Diagnósticos</a><a href="#protection-history">Histórico</a><a href="#protection-maintenance">Manutenção</a></nav>
<section id="protection-state" aria-labelledby="protection-state-title">
<h3 id="protection-state-title">Estado atual</h3>
<div class="amsfb-health-grid">
<?php foreach(['collector'=>'Coleta local','ai'=>'Análise automática','queue'=>'Fila recente','jail'=>'Jail da IA'] as $key=>$label): ?>
<div class="amsfb-health-card"><h4><?= $e($label) ?></h4><span class="label label-<?= $e($states[$key]['tone']) ?>"><?= $e($states[$key]['label']) ?></span>
<?php if($key==='collector'): ?><p><?= $e($date($health['collector']??0)) ?></p>
<?php elseif($key==='ai'): ?><p>Modo: <?= $e(['suggestion'=>'somente sugestões','threshold'=>'automático por critérios','auto'=>'automático imediato'][$values['ai_mode']]??$values['ai_mode']) ?><br>Último ciclo: <?= $e($date($lastRun)) ?></p>
<?php elseif($key==='queue'): ?><p><strong><?= $count($queue['ready']??null) ?></strong> tarefas prontas<br><?= $count($queue['backoff']??null) ?> em espera para nova tentativa</p>
<?php else: ?><p>Tickets na jail da IA: <?= $count(!empty($health['jail']['success'])?($health['jail']['ticket_count']??null):null) ?>.<br>Não é o total de IPs banidos no servidor.</p><?php endif ?>
</div><?php endforeach ?>
</div>
<?php if(!empty($health['collector_error'])||!empty($health['error'])): ?><div class="alert alert-danger" role="alert"><?= $e(trim(($health['collector_error']??'').' '.($health['error']??''))) ?></div><?php endif ?>
<?php if(!empty($queue['expiry']['warning'])): ?><div class="alert alert-warning" role="status">Há tarefas elegíveis próximas do vencimento: menor prazo restante de <?= (int)ceil(($queue['expiry']['seconds_remaining']??0)/60) ?> minuto(s). O aviso antecede a janela de <?= (int)$values['ai_analysis_recent_minutes'] ?> minutos; não reabre histórico nem executa bans.</div>
<?php elseif(!empty($queue['age_alert'])): ?><div class="alert alert-warning" role="status">A idade da fila elegível ultrapassou o limite de aviso configurado.</div><?php endif ?>
<?php if((int)$values['ai_queue_alert_minutes']>=(int)$values['ai_analysis_recent_minutes']): ?><p class="text-warning">O aviso de idade está em <?= (int)$values['ai_queue_alert_minutes'] ?> min, após a janela recente de <?= (int)$values['ai_analysis_recent_minutes'] ?> min. O aviso pré-expiração acima usa o prazo real dos eventos; ajuste os controles em Consumo se necessário.</p><?php endif ?>
<?php if((int)$values['ai_interval_minutes']>=(int)$values['ai_analysis_recent_minutes']): ?><p class="text-danger">O intervalo da IA é igual ou maior que a janela recente; eventos podem vencer antes da análise.</p><?php endif ?>
<p>Sondagem nativa configurada: <strong><?= $values['native_probe_enabled']==='1'?'habilitada':'desativada' ?></strong> · <?= (int)$values['native_probe_maxretry'] ?> tentativa(s) · <?= (int)$values['native_probe_bantime'] ?> segundos. Configuração não substitui conferência do firewall.</p>
<?php if(isset($health['retired_local'])): ?><p id="retired-local-summary">Rotas retiradas: <?= (int)$health['retired_local']['events'] ?> eventos representados em <?= (int)$health['retired_local']['tasks'] ?> agregações observadas localmente / <?= (int)$health['retired_local']['ips'] ?> IPs, no recorte das últimas <?= (int)$health['retired_local']['hours'] ?> horas. Não são bans nem estimativa de tokens economizados. Ajuste em Consumo.</p><?php endif ?>
<?php if(isset($health['simple_local'])): ?><p id="simple-local-summary">Triagem sem IA: <?= (int)$health['simple_local']['events'] ?> eventos representados em <?= (int)$health['simple_local']['tasks'] ?> agregações / <?= (int)$health['simple_local']['ips'] ?> IPs nas últimas <?= (int)$health['simple_local']['hours'] ?> horas; <?= (int)$health['simple_local']['static_tasks'] ?> agregações de assets e <?= (int)$health['simple_local']['normal_tasks'] ?> de rotas simples. São observações locais, não bans, análises da IA ou estimativa de tokens. Ajuste em Consumo.</p><?php endif ?>
<details class="amsfb-detail"><summary>Composição das pendências (<?= $count($health['backlog']??null) ?> tarefas) e proteção confirmada</summary>
<div class="table-responsive"><table class="table table-condensed"><thead><tr><th>Categoria</th><th>Tarefas</th></tr></thead><tbody>
<?php foreach(['ready'=>'Prontas agora','backoff'=>'Aguardando nova tentativa','review'=>'Revisão técnica recente','historical_deferred'=>'Histórico adiado','outside_window'=>'Fora da memória','awaiting_recheck'=>'Aguardando checagem de cobertura'] as $key=>$label): ?><tr><td><?= $e($label) ?></td><td><?= $count($queue[$key]??null) ?></td></tr><?php endforeach ?>
<tr><td>Suspensas por bloqueio efetivo</td><td><?= $count($blocked['held']??null) ?> tarefas / <?= $count($blocked['ips']??null) ?> IPs</td></tr></tbody></table></div>
<p>Pendência é tarefa, não IP atacante nem decisão de ban. As categorias usam a medição local; tarefas protegidas, antigas ou adiadas não contam como conclusão ou economia estimada de tokens.</p>
<p>Última rechecagem: <?= $e($date($blocked['last_check']??0)) ?> · <?= !empty($blocked['confirmed'])?'confirmação vigente':'confirmação vencida ou indisponível' ?>. <?= $e($blocked['error']??'') ?> Rechecagem na frequência real do cron; SSH bloqueado não comprova cobertura HTTP.</p>
</details>
</section>
<section id="protection-settings" aria-labelledby="protection-settings-title">
<h3 id="protection-settings-title">Configurações</h3>
<?php if($values['ai_query_probe_enabled']==='1'): ?>
<p id="query-timing-summary">Manipulação de query — política salva: <?= (int)$values['ai_query_probe_min_events'] ?> eventos individuais em até <?= (int)$queryTiming['window_minutes'] ?> min, com idade máxima efetiva de <?= (int)$queryTiming['decision_minutes'] ?> min por evento. Intervalo da IA: <?= (int)$queryTiming['interval_minutes'] ?> min; orçamento do ciclo: <?= (int)$queryTiming['cycle_seconds'] ?> s. Coleta, cron e fila podem acrescentar atraso.</p>
<?php if($queryTiming['warning']): ?><div id="query-timing-warning" class="alert alert-warning" role="status">O prazo efetivo da evidência de query é menor ou igual ao intervalo da IA mais o orçamento do ciclo. A sequência pode vencer antes da decisão. Revise o prazo em Manipulação de query e o limite de atividade recente em Consumo; ampliar a janela de repetição não substitui esse ajuste. Não há garantia de processamento antes do vencimento.</div><?php endif ?>
<?php endif ?>
<?php if($values['ai_auto_enabled']==='1'&&$values['ai_mode']!=='suggestion'&&($health['confirmed_auto']??'0')!=='1'): ?><p class="alert alert-warning">Bloqueio automático sem confirmação registrada. Salvar exige marcar o aceite de bloqueios automáticos; nenhum aceite será presumido por esta tela.</p><?php endif ?>
<p><a href="<?= $e($modulelink.'&action=ai_settings') ?>">Provedor, credenciais, prompt e whitelist</a>. Alterações nesta tela só entram em vigor após salvar.</p>
<?php if($error): ?><div class="alert alert-danger" role="alert"><?= $e($error) ?> Os valores enviados foram mantidos para conferência. Em conflito de versão, <a href="<?= $e($modulelink.'&action=protection') ?>">recarregue os valores atuais</a> antes de reaplicar somente os ajustes desejados.</div><?php endif ?>
<?php include __DIR__.'/protection_fields.tpl'; ?>
</section>
<details id="protection-diagnostics" class="amsfb-detail"><summary>Diagnósticos e simulação · <?= count($health['native_detection_quarantine']??[]) ?> quarentenas registradas</summary>
<?php include __DIR__.'/protection_diagnostics.tpl'; ?>
</details>
<details id="protection-history" class="amsfb-detail"><summary>Histórico de trabalhos · <?= count($jobs) ?> recentes</summary>
<p>Estes são resultados históricos, não a saúde atual do firewall. Campos null significam não medido. Evidências originais permanecem preservadas.</p>
<div class="table-responsive"><table class="table table-striped"><thead><tr><th>Trabalho e atualização</th><th>Estado</th><th>Resumo</th></tr></thead><tbody>
<?php foreach($jobs as $job): $result=json_decode($job['result']??'{}',true)?:[];$monitor=$result['monitor']??[]; ?>
<tr><td><code><?= $e($job['id']) ?></code><br><?= $e($job['updated_at']) ?></td><td><?= $e($code($job['status'])) ?></td><td>
<?= $count($result['archive_parts']??null) ?> partes arquivadas · <?= $count($result['unbanned']??null) ?> tickets liberados
<?php if($monitor): ?><br><?= (int)($monitor['samples']??0) ?> amostras · <?= (int)($monitor['errors']??0) ?> erros registrados · máximo histórico de regras ausentes: <?= isset($monitor['max_missing_rules'])?(int)$monitor['max_missing_rules']:'não medido' ?><?php endif ?>
<?php if(!empty($result['error'])): ?><p class="text-danger"><?= $e($result['error']) ?></p><?php endif ?>
<details><summary>Detalhes resumidos deste trabalho</summary><pre><?= $e($job['result']??'') ?></pre><p>Listas técnicas por jail das amostras originais não são carregadas nesta tela.</p></details>
<?php if($job['status']==='failed'): ?><a href="#protection-maintenance">Abrir manutenção para avaliar retomada</a><?php endif ?>
</td></tr><?php endforeach ?>
</tbody></table></div>
</details>
<details id="protection-maintenance" class="amsfb-detail"><summary>Manutenção pontual e revisão técnica</summary>
<?php include __DIR__.'/protection_maintenance.tpl'; ?>
</details>
</div>
<script src="<?= $e(($asset_base??\AMS\Fail2Ban\Helper::assetBase()).'js/protection.js?v=2.2.53') ?>"></script>
