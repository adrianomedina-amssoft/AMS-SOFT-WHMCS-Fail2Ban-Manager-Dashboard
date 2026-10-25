<?php
/** Read-only overview. Counts from daemon, module history and decisions have distinct scopes. */
$n=$overview['native']; $history=$overview['history']; $ai=$overview['ai'];
$decisions=$overview['decisions']; $last=$history['last']??null; $analysis=$overview['last_analysis'];
$count=fn($v)=>\AMS\Fail2Ban\ProtectionView::count($v);
$stamp=fn($v)=>is_numeric($v)&&(int)$v>0&&(int)$v<=time()?date('d/m/Y H:i:s',(int)$v):'não confirmado';
$json=fn($v)=>json_encode($v,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE);
?>
<div class="amsfb-page-header">
    <h3>&#9776; Dashboard</h3>
    <span class="label <?= $n['complete']?'label-success':'label-warning' ?>">
        <?= $n['complete']?'Fail2Ban consultado':($n['online']?'Fail2Ban: leitura parcial':'Fail2Ban: consulta indisponível') ?>
    </span>
</div>
<p class="text-muted">Leitura de <?= $e($stamp($overview['at'])) ?> a <?= $e($stamp($overview['finished_at'])) ?>
    (<?= $e(date_default_timezone_get()) ?>). Atualize a página para consultar novamente.</p>
<?php foreach (array_merge($n['error']?[$n['error']]:[], $overview['errors']) as $message): ?>
<div class="alert alert-warning" role="alert"><?= $e($message) ?></div>
<?php endforeach; ?>

<div class="row amsfb-kpi-row">
    <div class="col-sm-3"><div class="amsfb-kpi-card amsfb-kpi-red">
        <div class="amsfb-kpi-value" data-kpi="native-ips"><?= $e($count($n['unique_ips'])) ?></div>
        <div class="amsfb-kpi-label">IPs únicos com ban no Fail2Ban</div>
    </div></div>
    <div class="col-sm-3"><div class="amsfb-kpi-card amsfb-kpi-orange">
        <div class="amsfb-kpi-value" data-kpi="module-24h"><?= $e($count($history['count_24h']??null)) ?></div>
        <div class="amsfb-kpi-label">Bans registrados pelo módulo — 24h</div>
    </div></div>
    <div class="col-sm-3"><div class="amsfb-kpi-card amsfb-kpi-blue">
        <div class="amsfb-kpi-value" data-kpi="active-jails"><?= $e($count($n['jails'])) ?></div>
        <div class="amsfb-kpi-label">Jails carregadas no Fail2Ban</div>
    </div></div>
    <div class="col-sm-3"><div class="amsfb-kpi-card amsfb-kpi-green">
        <div class="amsfb-kpi-value amsfb-kpi-sm" data-kpi="last-module-ban"><?= $e($last['ip']??($history===null?'não medido':'nenhum registro')) ?></div>
        <div class="amsfb-kpi-label">Último ban registrado pelo módulo</div>
        <?php if ($last): ?>
        <small style="display:block;overflow-wrap:anywhere"><?= $e($last['timestamp']) ?> · <?= $e($last['jail']) ?></small>
        <?php if (!empty($overview['geo'][$last['ip']])): ?>
        <div class="amsfb-kpi-geo"><?= $e(\AMS\Fail2Ban\GeoIP::formatGeo($overview['geo'][$last['ip']])) ?> (cache)</div>
        <?php endif; endif; ?>
    </div></div>
</div>
<p class="text-muted" style="margin-top:10px">
    O mesmo IP pode ter tickets em várias jails. <?= $e($count($n['tickets'])) ?> tickets nesta leitura.
    Ticket no daemon não comprova sozinho cobertura no firewall.
    <a href="<?= $e($modulelink.'&action=protection') ?>">Conferir proteção efetiva</a>.
    O histórico do módulo não inclui todos os bans nativos; ban anterior não significa bloqueio vigente.
</p>

<div class="panel amsfb-ai-panel" style="margin-top:20px">
    <div class="panel-heading"><strong>&#129302; IA e decisões</strong>
        <a href="<?= $e($modulelink.'&action=ai_settings') ?>" class="btn btn-xs btn-default pull-right">Configurações da IA</a>
    </div>
    <div class="panel-body">
        <?php if ($ai): ?>
        <?php $modes=['suggestion'=>'Somente sugestões','auto'=>'Automático','threshold'=>'Automático por critérios']; ?>
        <p>
            <strong>Automação: <?= $ai['enabled']?'ligada':'desligada' ?></strong>.
            Modo configurado: <?= $e($modes[$ai['mode']]??'não reconhecido') ?>.
            <?php if (!$ai['enabled']): ?>O modo configurado não está sendo executado automaticamente.<?php endif; ?>
        </p>
        <p>
            <?php foreach (['collector'=>'Coleta','ai'=>'Ciclo da IA'] as $key=>$label): $state=$ai['states'][$key]; ?>
            <?= $e($label) ?>:
            <span class="label label-<?= $e($state['tone']) ?>"><?= $e($state['label']) ?></span>
            <small>(<?= $e($stamp($ai[$key==='collector'?'collector':'cycle'])) ?>)</small>
            <?php endforeach; ?>
        </p>
        <p class="text-muted">
            Provedor: <?= $e($ai['provider']) ?>.
            Teste salvo da API: <?= $ai['saved_ping']==='1'?'sucesso':'sem sucesso confirmado' ?>.
            Esse teste não confirma disponibilidade atual; abrir esta página não testa nem chama a API.
        </p>
        <?php else: ?><p>Estado da automação não medido.</p><?php endif; ?>
        <div class="row">
            <div class="col-sm-4">
                <div style="font-size:30px;font-weight:bold" data-kpi="actionable"><?= $e($count($decisions['counts']['actionable']??null)) ?></div>
                <p>Decisões acionáveis <small>(registros, não IPs únicos)</small></p>
                <a href="<?= $e($modulelink.'&action=ai&decision_view=actionable') ?>" class="btn btn-sm btn-default">Ver decisões</a>
                <?php if ($decisions): ?>
                <ul style="margin-top:10px">
                <?php foreach (['waiting'=>'Aguardando critérios','protected'=>'Já protegidos','checking'=>'Aguardando checagem','review'=>'Revisão técnica','history'=>'Decisões históricas'] as $view=>$label): ?>
                    <li><a href="<?= $e($modulelink.'&action=ai&decision_view='.$view) ?>"><?= $e($label) ?>: <?= $e($count($decisions['counts'][$view]??null)) ?></a></li>
                <?php endforeach; ?>
                </ul>
                <small class="text-muted">Consulta das decisões: <?= $e($stamp($decisions['at'])) ?>.</small>
                <?php endif; ?>
            </div>
            <div class="col-sm-8">
                <?php if ($analysis): ?>
                <?php
                $types=['ban'=>'Proposta de bloqueio','monitor'=>'Observação — sem bloqueio','whitelist'=>'Sugestão de confiança — não altera a whitelist'];
                $statuses=['pending'=>'Pendente no histórico de análises','approved'=>'Aprovada','rejected'=>'Rejeitada','auto_executed'=>'Executada automaticamente'];
                $severities=['low'=>'Baixa','medium'=>'Média','high'=>'Alta','critical'=>'Crítica'];
                ?>
                <table class="table table-condensed amsfb-table">
                    <caption>Última análise registrada — pode não exigir bloqueio</caption>
                    <tbody>
                    <tr><th scope="row">IP</th><td><?= $e($analysis['ip']) ?></td></tr>
                    <tr><th scope="row">Classificação</th><td><?= $e($types[$analysis['classification']]??'Não reconhecida') ?></td></tr>
                    <tr><th scope="row">Descrição</th><td style="overflow-wrap:anywhere"><?= $e($analysis['threat']) ?></td></tr>
                    <tr><th scope="row">Severidade / confiança</th><td><?= $e($severities[$analysis['severity']]??'Não reconhecida') ?> / <?= (int)$analysis['confidence'] ?>% na classificação</td></tr>
                    <tr><th scope="row">Status do registro</th><td><?= $e($statuses[$analysis['status']]??'Não reconhecido') ?></td></tr>
                    <tr><th scope="row">Registrada em</th><td><?= $e($analysis['created_at']) ?></td></tr>
                    </tbody>
                </table>
                <small class="text-muted">O status histórico não comprova proteção atual. As categorias ao lado consideram proteção e critérios vigentes.</small>
                <?php elseif ($overview['last_analysis_known']): ?>
                <p class="text-muted">Nenhuma análise registrada. Consulte as configurações e o estado da coleta.</p>
                <?php else: ?><p class="text-muted">Última análise não medida.</p><?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php if (($history['created_today']??0)>0): ?>
<div class="alert alert-info">
    <strong><?= (int)$history['created_today'] ?> criação(ões) de jail registrada(s) hoje</strong>.
    O registro pode ter origem manual ou automática; não comprova que a jail continua ativa.
    <ul><?php foreach ($history['created_recent'] as $event): ?>
        <li><code><?= $e($event['jail']) ?></code> — <?= $e($event['timestamp']) ?></li>
    <?php endforeach; ?></ul>
    <a href="<?= $e($modulelink.'&action=reports&filter_action=jail_created') ?>">Ver histórico de criação</a>
</div>
<?php endif; ?>

<div class="row" style="margin-top:20px">
    <div class="col-md-7"><div class="panel panel-default">
        <div class="panel-heading"><strong>Bans do módulo — sete dias de calendário, incluindo hoje</strong></div>
        <div class="panel-body">
            <?php if ($history!==null): ?>
            <canvas id="chartBansSeries" height="120" role="img" aria-label="Bans do módulo por dia; valores na tabela abaixo"></canvas>
            <details><summary>Ver valores por dia</summary>
                <table class="table table-condensed"><thead><tr><th scope="col">Data</th><th scope="col">Registros de ban</th></tr></thead><tbody>
                <?php foreach ($history['days'] as $day): ?>
                <tr><td><?= $e($day['date']) ?></td><td><?= (int)$day['count'] ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            </details>
            <?php else: ?><p>Histórico não medido.</p><?php endif; ?>
        </div>
    </div></div>
    <div class="col-md-5"><div class="panel panel-default">
        <div class="panel-heading"><strong>Top 10 IPs — histórico retido do módulo</strong></div>
        <div class="panel-body">
            <?php if ($history!==null && $history['top']): ?>
            <canvas id="chartTopIps" height="200" role="img" aria-label="IPs com mais registros de ban no módulo; valores na tabela abaixo"></canvas>
            <details><summary>Ver IPs e contagens</summary>
                <table class="table table-condensed"><thead><tr><th scope="col">IP</th><th scope="col">Registros de ban</th></tr></thead><tbody>
                <?php foreach ($history['top'] as $row): ?>
                <tr><td><?= $e($row['ip']) ?></td><td><?= (int)$row['count'] ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            </details>
            <?php else: ?><p><?= $history===null?'Histórico não medido.':'Nenhum ban registrado pelo módulo.' ?></p><?php endif; ?>
        </div>
    </div></div>
</div>

<?php if ($n['statuses']): ?>
<div class="panel panel-default">
    <div class="panel-heading"><strong>Contadores por jail carregada</strong></div>
    <div class="table-responsive">
        <table class="table table-striped table-hover amsfb-table">
            <caption style="padding:10px">Totais da execução de cada jail, não das últimas 24 horas. Podem mudar após reinício/reload. Uma jail carregada não comprova ação eficaz no firewall.</caption>
            <thead><tr><th scope="col">Jail</th><th scope="col">Tickets atuais</th><th scope="col">Total de bans</th><th scope="col">Falhas atuais</th><th scope="col">Total de falhas</th></tr></thead>
            <tbody>
            <?php foreach ($n['statuses'] as $jail=>$row): ?>
            <tr><th scope="row"><a href="<?= $e($modulelink.'&action=jail_edit&jail='.urlencode($jail)) ?>"><?= $e($jail) ?></a></th>
                <?php foreach (['currently_banned','total_banned','currently_failed','total_failed'] as $key): ?>
                <td><?= $e($count($row[$key]??null)) ?></td>
                <?php endforeach; ?>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php elseif ($n['complete']): ?><p>Nenhuma jail carregada.</p><?php endif; ?>

<script>
document.addEventListener('DOMContentLoaded', function () {
    if (typeof Chart === 'undefined') return;
    var days = <?= $json($history['days']??[]) ?>;
    var top = <?= $json($history['top']??[]) ?>;
    var line = document.getElementById('chartBansSeries');
    var bar = document.getElementById('chartTopIps');
    if (line) new Chart(line, {
        type: 'line',
        data: {labels: days.map(function(r){return r.date;}), datasets: [{
            label: 'Registros de ban no módulo', data: days.map(function(r){return Number(r.count);}),
            borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', tension: 0.3, fill: true
        }]},
        options: {responsive: true, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, ticks: {precision: 0}}}}
    });
    if (bar) new Chart(bar, {
        type: 'bar',
        data: {labels: top.map(function(r){return r.ip;}), datasets: [{
            label: 'Registros de ban no módulo', data: top.map(function(r){return Number(r.count);}), backgroundColor: '#3498db'
        }]},
        options: {indexAxis: 'y', responsive: true, plugins: {legend: {display: false}}, scales: {x: {beginAtZero: true, ticks: {precision: 0}}}}
    });
});
</script>
