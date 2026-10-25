<?php
$simulation=$simulation??['status'=>'awaiting_measurement','report'=>[],'error'=>''];
$simReport=$simulation['report']??[];
$simLabels=['disabled'=>'Desativada','awaiting_measurement'=>'Aguardando medição pelo cron',
    'measured'=>'Medição local disponível','coverage_unavailable'=>'Proteção não confirmada; candidatos não avaliados',
    'expired'=>'Medição vencida; aguarde o cron','policy_changed'=>'Política alterada; aguarde nova medição'];
?>
<div class="panel panel-default" id="amsfb-probe-simulation"><div class="panel-heading"><strong>Simulação local de sondagens — sem bloqueio</strong></div><div class="panel-body">
<p><?= $e($simLabels[$simulation['status']]??'Medição indisponível') ?>. Esta simulação não chama a IA, não cria filtros e não executa bans. O catálogo ativo e a confiança mínima da automação permanecem independentes.</p>
<?php if(!empty($simulation['error'])): ?><p class="text-warning"><?= $e($simulation['error']) ?></p><?php endif ?>
<?php if(!empty($simReport['at'])): ?>
<p>Medição: <?= $e(date('d/m/Y H:i:s',$simReport['at'])) ?> · validade da consulta de proteção até <?= $e(date('H:i:s',$simReport['valid_until']??0)) ?> · janela <?= (int)$simReport['window_minutes'] ?> min. Critério simulado: <?= (int)$simReport['min_events'] ?> eventos / <?= (int)$simReport['min_apps'] ?> aplicações distintas por IP e origem.</p>
<p><?= (int)$simReport['subjects'] ?> pares IP/origem representados; <?= (int)$simReport['criteria_met'] ?> atingiram os mínimos na medição. Excluídos: <?= (int)$simReport['excluded_protected'] ?> pares protegidos, <?= (int)$simReport['excluded_unknown'] ?> com proteção desconhecida e <?= (int)$simReport['excluded_whitelist'] ?> IPs em whitelist. Nenhum resultado é autorização de bloqueio.</p>
<?php if(!empty($simReport['partial'])): ?><p class="text-warning">Amostra parcial: existem limites de leitura ou eventos não representados integralmente. Ausência de candidatos não comprova ausência de sondagem.</p><?php endif ?>
<?php if(!empty($simReport['display_limited'])): ?><p>Exibição limitada aos 25 pares prioritários da medição.</p><?php endif ?>
<?php if(!empty($simReport['results'])): ?><div class="table-responsive"><table class="table table-striped"><thead><tr><th>IP e origem</th><th>Eventos e aplicações</th><th>Alvos representados</th><th>Resultado simulado</th></tr></thead><tbody>
<?php foreach($simReport['results'] as $candidate): ?><tr><td><?= $e($candidate['ip']) ?><br><small><?= $e($candidate['source_log']) ?></small></td><td><?= (int)$candidate['events'] ?> eventos / <?= (int)$candidate['applications'] ?> aplicações<br><?= $e(implode(', ',$candidate['groups'])) ?></td><td><?= $e(implode(', ',$candidate['paths'])) ?><br><small>Último evento: <?= $e(date('d/m H:i:s',$candidate['latest'])) ?></small></td><td><?= $e($candidate['criteria_met']?'Mínimos simulados atingidos — sem ban':'Abaixo dos mínimos simulados') ?><?php if($simulation['status']!=='measured'): ?><br><strong>Medição anterior, não vigente</strong><?php endif ?></td></tr><?php endforeach ?>
</tbody></table></div><?php endif ?>
<?php endif ?>
<small>Configuração em Proteção adaptativa → Simulação sem bloqueio. Só amostras recentes presentes, com peer e horário coerentes; não combina IPs, origens ou histórico truncado como prova. Não atribui botnet por rede, país ou User-Agent.</small>
</div></div>
