<?php
/**
 * AI Suggestions template — fila de sugestões pendentes + histórico
 * Disponível: $pending (array), $history (array), $filters (array)
 */

$severityLabels = [
    'low'      => ['label' => 'Baixa',    'class' => 'amsfb-sev-low'],
    'medium'   => ['label' => 'Média',    'class' => 'amsfb-sev-medium'],
    'high'     => ['label' => 'Alta',     'class' => 'amsfb-sev-high'],
    'critical' => ['label' => 'Crítica',  'class' => 'amsfb-sev-critical'],
];

$statusLabels = [
    'pending'       => ['label' => 'Pendente',       'class' => 'label-warning'],
    'approved'      => ['label' => 'Aprovada',        'class' => 'label-success'],
    'rejected'      => ['label' => 'Rejeitada',       'class' => 'label-default'],
    'auto_executed' => ['label' => 'Auto-executada',  'class' => 'label-info'],
];
?>

<div class="amsfb-page-header">
    <h3>&#129302; Sugestões da IA</h3>
    <button id="amsfb-run-now-btn" class="btn btn-sm btn-primary">
        &#9654; Analisar agora
    </button>
    <button id="amsfb-stop-btn" class="btn btn-sm btn-danger" style="display:none;">
        &#9726; Parar
    </button>
    <a href="<?= $e($modulelink . '&action=ai_settings') ?>" class="btn btn-sm btn-default">&#9881; Configurações</a>
</div>
<ul class="nav nav-tabs" id="amsfb-ai-tabs" style="margin-bottom:15px">
    <?php $decision_view=$decision_view??'actionable';$decision_counts=$decision_counts??['actionable'=>$pending_total];
    $decisionLabels=['actionable'=>'Decisões de bloqueio','waiting'=>'Aguardando critérios','protected'=>'Já protegidos','checking'=>'Aguardando checagem','review'=>'Revisão técnica','history'=>'Decisões históricas'];
    foreach($decisionLabels as $view=>$label): ?><li class="<?= $view===$decision_view?'active':'' ?>"><a href="<?= $e($modulelink.'&action=ai&decision_view='.$view) ?>"><?= $e($label) ?> (<?= (int)($decision_counts[$view]??0) ?><?= isset($dashboard['decisions'][$view])?' decisões / '.(int)$dashboard['decisions'][$view]['ips'].' IPs':'' ?>)</a></li><?php endforeach ?>
    <li><a href="#amsfb-observations" data-toggle="tab">Observações (<?= (int)($dashboard['observation_stats']['counts']['all']??$observations_total??0) ?>)</a></li>
    <?php if(isset($dashboard['learning'])): ?><li><a href="#amsfb-learning" data-toggle="tab">Aprendizado (<?= (int)$dashboard['learning']['counts']['pending'] ?> pendentes / <?= (int)$dashboard['learning']['counts']['review'] ?> em revisão)</a></li><?php endif ?>
    <li><a href="#amsfb-history" data-toggle="tab">Histórico</a></li>
</ul>
<p class="text-muted">Confiança indica certeza da classificação, não probabilidade de ataque. A automação não depende desta tela aberta.</p>
<p class="text-muted">Protegidos confirmados não entram nas decisões acionáveis nem são reenviados à IA, inclusive manualmente. Consulta indisponível aguarda checagem local. Os registros e vencimentos dos bans são preservados. Filtro sugerido não é comprovação de cobertura.</p>
<?php if(isset($dashboard['queue'])): $queue=$dashboard['queue'];$decisionStats=$dashboard['decisions'][$decision_view]??null; ?>
<div class="panel panel-default" id="amsfb-operational-summary"><div class="panel-heading"><strong>Análise e aprendizado são filas diferentes</strong></div><div class="panel-body">
    <p>Consulta de proteção: <?= $e(date('d/m/Y H:i:s',$dashboard['protection_at'])) ?>. Resumo: <?= $e(date('d/m/Y H:i:s',$dashboard['at'])) ?>. Evidência recente: últimos <?= (int)$dashboard['recent_minutes'] ?> minutos.</p>
    <?php if($decisionStats): ?><p>Nesta categoria: <?= (int)$decisionStats['records'] ?> decisões / <?= (int)$decisionStats['ips'] ?> IPs distintos; <?= (int)$decisionStats['recent'] ?> com evidência recente, <?= (int)$decisionStats['history'] ?> antiga e <?= (int)$decisionStats['undated'] ?> sem data comprovada. Proteção atual não torna a evidência antiga recente.</p><?php endif ?>
    <?php $reasonLabels=['pending_new_analysis'=>'Atividade nova aguardando análise; decisões anteriores são históricas',
        'confidence_low'=>'Confiança abaixo do limite','waiting_threshold'=>'Repetição validada insuficiente',
        'waiting_query_criteria'=>'Manipulação suspeita — aguardando repetição individual validada','waiting_application_criteria'=>'Eventos ou aplicações validados insuficientes','waiting_php_criteria'=>'Falhas ou alvos PHP validados insuficientes','proof_validation_pending'=>'Validação da prova pendente',
        'coverage_unavailable'=>'Consulta da proteção indisponível','service_unknown'=>'Serviço não identificado',
        'effective_coverage'=>'Bloqueio efetivo confirmado','evidence_expired'=>'Evidência fora da janela atual',
        'individual_multi_target'=>'Múltiplos alvos individualmente validados','individual_application_probe'=>'Aplicações individualmente validadas','individual_php_scan'=>'Varredura PHP individualmente validada',
        'criteria_met'=>'Critérios atuais atingidos','non_offensive_signal'=>'Sinal isolado sem autoridade de bloqueio']; ?>
    <?php foreach($dashboard['decision_reasons'][$decision_view]??[] as $reason): ?><p class="amsfb-decision-reason"><?= $e($reasonLabels[$reason['reason']]??$reason['reason']) ?>: <?= (int)$reason['records'] ?> registros / <?= (int)$reason['ips'] ?> IPs únicos<?php if($reason['historical']): ?>; <?= (int)$reason['historical'] ?> registros com evidência antiga<?php endif ?>.</p><?php endforeach ?>
    <?php if($decision_view==='checking'): ?><p>Checagem não significa ataque novo confirmado. Várias decisões antigas do mesmo IP podem reaparecer enquanto uma tarefa recente é analisada; o total de registros não é o total de atacantes.</p><?php endif ?>
    <p>Tarefas de análise recentes prontas: <?= (int)$queue['ready'] ?>; em backoff: <?= (int)$queue['backoff'] ?>; aguardando rechecagem local: <?= (int)$queue['awaiting_recheck'] ?>; históricas adiadas: <?= (int)$queue['historical_deferred'] ?>.</p>
    <p>Aprendizado: <?= (int)$dashboard['learning']['counts']['pending'] ?> pendentes; <?= (int)$dashboard['learning']['counts']['criteria'] ?> resultados com critérios insuficientes; <?= (int)$dashboard['learning']['counts']['review'] ?> em revisão técnica; <?= (int)$dashboard['learning']['counts']['completed'] ?> concluídos. São resultados por decisão, não filtros distintos.</p>
    <p class="text-muted">Zero decisões de bloqueio significa nenhuma decisão elegível agora, não ausência de sondagens ou de tarefas. Revisão de decisões não inclui a revisão do aprendizado. Resultados de aprendizado antigos não são reenfileirados por esta consulta.</p>
</div></div>
<?php endif ?>
<?php $simulation=$dashboard['simulation']??null;if($simulation)include __DIR__.'/probe_simulation.tpl'; ?>
<div class="tab-content">
<div class="tab-pane active" id="amsfb-decisions">

<!-- =========================================================
     Seção 0: Ações por País (bulk)
     ========================================================= -->
<?php if (!empty($country_groups)): ?>
<div class="panel panel-default amsfb-country-panel">
    <div class="panel-heading">
        <strong>&#127758; Decisões por país — registros, não IPs distintos</strong>
        <span class="badge" style="background:#337ab7; margin-left:8px;"><?= count($country_groups) ?></span>
    </div>
    <div class="panel-body">
        <div class="amsfb-country-grid">
        <?php foreach ($country_groups as $cg):
            $cc = $cg['country_code'];
            $flag = $cc !== '' ? \AMS\Fail2Ban\GeoIP::countryToFlag($cc) : '&#127760;';
            $label = $e($cg['country']);
        ?>
            <div class="amsfb-country-card" data-country-code="<?= $e($cc) ?>">
                <div>
                    <span class="amsfb-country-flag"><?= $flag ?></span>
                    <span class="amsfb-country-name"><?= $label ?></span>
                    <span class="amsfb-country-count"><?= (int)$cg['ip_count'] ?></span>
                </div>
                <div class="amsfb-country-actions">
                    <button class="btn btn-xs btn-default amsfb-select-country"
                            data-country-code="<?= $e($cc) ?>"
                            data-country-name="<?= $label ?>"
                            title="Selecionar todos os IPs deste país na tabela abaixo">
                        &#9745; Selecionar
                    </button>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- =========================================================
     Seção 1: Fila Pendente
     ========================================================= -->
<div class="panel panel-default amsfb-pending-panel">
    <div class="panel-heading">
        <strong>&#9203; <?= $e($decisionLabels[$decision_view]) ?></strong>
        <?php if ($pending_total > 0): ?>
        <span class="badge" style="background:#e74c3c; margin-left:8px;"><?= (int)$pending_total ?></span>
        <?php endif; ?>
    </div>

    <?php if (empty($pending)): ?>
    <div class="panel-body text-muted">Nenhuma decisão nesta categoria. Consulte as tarefas de análise, aprendizado e o histórico para acompanhar a operação.</div>
    <?php endif; ?>
    <div class="table-responsive">
        <table class="table table-striped table-hover amsfb-table amsfb-table-sm">
            <thead>
                <tr>
                    <th style="width:30px"><input type="checkbox" id="amsfb-select-all" title="Selecionar todos desta página" <?= $decision_view!=='actionable'?'disabled':'' ?>></th>
                    <th>IP</th>
                    <th>Ameaça</th>
                    <th>Severidade</th>
                    <th title="Certeza da classificação da IA">Confiança da classificação</th>
                    <th>Jail</th>
                    <th>Filtro</th>
                    <th>Bantime</th>
                    <th>Evento / análise</th>
                    <th>Ações</th>
                </tr>
            </thead>
            <tbody id="amsfb-pending-tbody">
            <?php foreach ($pending as $s): ?>
                <tr id="amsfb-row-<?= (int)$s['id'] ?>"
                    class="<?= (int)$s['confidence']<\AMS\Fail2Ban\Policy::number('ai_min_confidence')?'text-muted':'' ?>"
                    data-country-code="<?= $e($geo_data[$s['ip']]['country_code'] ?? '') ?>">
                    <td><input type="checkbox" class="amsfb-row-cb" data-id="<?= (int)$s['id'] ?>" <?= !empty($s['effectively_protected'])||$decision_view!=='actionable'?'disabled':'' ?>></td>
                    <td>
                        <strong><?= $e($s['ip']) ?></strong>
                        <?php if (!empty($geo_data[$s['ip']])): ?>
                        <br><small class="amsfb-geo-info"><?= $e(\AMS\Fail2Ban\GeoIP::formatGeo($geo_data[$s['ip']])) ?></small>
                        <?php endif; ?>
                    </td>
                    <td><?= $e($s['threat']) ?><br><small><?= $e($s['decision_label']??'Decisão histórica — motivo não medido') ?></small><?php if(!empty($s['proof_summary'])): ?><br><small><?= $e($s['proof_summary']) ?></small><?php endif ?></td>
                    <td>
                        <span class="<?= $e($severityLabels[$s['severity']]['class'] ?? 'amsfb-sev-medium') ?>">
                            <?= $e($severityLabels[$s['severity']]['label'] ?? $s['severity']) ?>
                        </span>
                    </td>
                    <td>
                        <div class="amsfb-confidence-bar">
                            <div class="amsfb-confidence-fill" style="width:<?= (int)$s['confidence'] ?>%"></div>
                            <span><?= (int)$s['confidence'] ?>%</span>
                        </div>
                    </td>
                    <td><?= $e($s['executed_jail']??'-') ?><br><small>Destino sugerido: <?= $e($s['jail'] ?: '-') ?></small><br><small><?= $e($s['protection_label']??'Cobertura não verificada') ?></small></td>
                    <td>
                        <?php if (!empty($s['filter_name'])): ?>
                            <code style="font-size:11px;"
                                  title="failregex: <?= $e($s['failregex'] ?? '') ?>">amsfb-<?= $e($s['filter_name']) ?></code>
                            <br><small><?= $e($s['filter_state']??'Estado não conferido') ?></small>
                            <?php if(!empty($s['promotion'])): ?><br><small>Aprendizado: <?= $e($s['promotion']['code']??'não medido') ?> — <?= $e($s['promotion']['learning_state']??'resultado nativo') ?> — <?= $e($s['promotion']['jail']??'-') ?></small><?php endif ?>
                        <?php else: ?>
                            <span class="text-muted">-</span>
                        <?php endif; ?>
                    </td>
                    <td><?= $s['bantime'] ? $e($s['bantime'] . 's') : '-' ?></td>
                    <td><small>Evento: <?= $e($s['evidence_latest_at']??'não medido') ?></small><br><small>Análise: <?= $e($s['created_at'] ?? '-') ?></small></td>
                    <td class="amsfb-action-btns">
                        <button class="btn btn-xs btn-success amsfb-approve-btn"
                                <?= !empty($s['effectively_protected'])||$decision_view!=='actionable'?'disabled':'' ?>
                                data-id="<?= (int)$s['id'] ?>"
                                title="<?= !empty($s['effectively_protected'])?'Já protegido; atualize a tela após o prazo da confirmação':'Confirmar bloqueio deste IP' ?>">
                            &#128683; Banir IP
                        </button>
                        <button class="btn btn-xs btn-danger amsfb-reject-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                title="Rejeitar sugestão">
                            &#10007; Rejeitar
                        </button>
                        <button class="btn btn-xs btn-info amsfb-evidence-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                data-evidence="<?= $e(json_encode($s['evidence'] ?? [])) ?>"
                                title="Ver evidências">
                            &#128220; Evidências
                        </button>
                        <?php if (!empty($s['suggested_rule'])): ?>
                        <button class="btn btn-xs btn-warning amsfb-rule-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                data-rule="<?= $e($s['suggested_rule']) ?>"
                                title="Ver regra sugerida">
                            &#128196; Regra
                        </button>
                        <?php endif; ?>
                        <?php if (!empty($s['failregex']) || !empty($s['evidence'])): ?>
                        <button class="btn btn-xs btn-default amsfb-create-filter-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                data-filter-name="<?= $e($s['filter_name'] ?? '') ?>"
                                data-has-regex="<?= !empty($s['failregex']) ? '1' : '0' ?>"
                                data-failregex="<?= $e($s['failregex'] ?? '') ?>"
                                <?= ($s['decision_code']??'')==='promotion_queued' ? 'disabled' : '' ?>
                                title="Enfileirar aprendizado nativo validado; sem chamada extra à IA e sem reativar quarentenas">
                            <?= ($s['decision_code']??'')==='promotion_queued' ? 'Aprendizado solicitado' : 'Solicitar aprendizado' ?>
                        </button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Barra de ação em massa (aparece quando checkboxes são marcados) -->
    <div id="amsfb-bulk-bar" class="amsfb-bulk-bar" style="display:none">
        <span id="amsfb-bulk-count">0 selecionado(s)</span>
        <button id="amsfb-bulk-approve-btn" class="btn btn-sm btn-success">&#128683; Banir Selecionados</button>
        <button id="amsfb-bulk-reject-btn" class="btn btn-sm btn-danger">&#10007; Rejeitar Selecionados</button>
        <button id="amsfb-bulk-clear-btn" class="btn btn-sm btn-default">Limpar</button>
    </div>

    <!-- Paginação da fila pendente -->
    <?php if ($pending_pages > 1): ?>
    <div class="amsfb-pagination-wrap">
        <nav aria-label="Paginação pendentes">
            <ul class="pagination pagination-sm">
                <?php if ($pending_page > 1): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&decision_view='.$decision_view.'&pending_page=' . ($pending_page - 1)) ?>">&laquo;</a>
                </li>
                <?php endif; ?>

                <?php
                $pStart = max(1, $pending_page - 3);
                $pEnd   = min($pending_pages, $pending_page + 3);
                for ($p = $pStart; $p <= $pEnd; $p++):
                ?>
                <li class="<?= $p === $pending_page ? 'active' : '' ?>">
                    <a href="<?= $e($modulelink . '&action=ai&decision_view='.$decision_view.'&pending_page=' . $p) ?>"><?= $p ?></a>
                </li>
                <?php endfor; ?>

                <?php if ($pending_page < $pending_pages): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&decision_view='.$decision_view.'&pending_page=' . ($pending_page + 1)) ?>">&raquo;</a>
                </li>
                <?php endif; ?>
            </ul>
        </nav>
        <p class="text-muted amsfb-pagination-info">
            <?= (int)$pending_total ?> sugestão(ões) pendente(s) &mdash; página <?= (int)$pending_page ?> de <?= (int)$pending_pages ?>
        </p>
    </div>
    <?php endif; ?>

</div>

<!-- =========================================================
     Seção 2: Histórico com filtros
     ========================================================= -->
</div>
<div class="tab-pane" id="amsfb-observations">
<div class="panel panel-default">
    <div class="panel-heading"><strong>Observações — sem bloqueio</strong></div>
    <div class="panel-body text-muted">A classificação “whitelist” é uma recomendação da IA, não uma inclusão automática na lista de confiança.</div>
    <?php if(isset($dashboard['observation_stats'])): $obsStats=$dashboard['observation_stats'];$observation_scope=$observation_scope??'all'; ?>
    <div class="panel-body" id="amsfb-observation-summary">
        <p><?= (int)$obsStats['counts']['all'] ?> registros / <?= (int)$obsStats['ips'] ?> IPs distintos; <?= (int)$obsStats['counts']['recent'] ?> recentes, <?= (int)$obsStats['counts']['history'] ?> históricos e <?= (int)$obsStats['undated'] ?> sem data comprovada.</p>
        <p>Vetores explícitos para triagem local: <?= (int)$obsStats['counts']['review'] ?>. Isso não confirma ataque, não autoriza ban nem chama IA. A classificação original permanece.</p>
        <?php foreach(['all'=>'Todas','recent'=>'Recentes','history'=>'Históricas','review'=>'Vetores para revisar'] as $scope=>$label): ?><a class="btn btn-xs <?= $scope===$observation_scope?'btn-primary':'btn-default' ?>" href="<?= $e($modulelink.'&action=ai&decision_view='.$decision_view.'&observation_scope='.$scope.'#amsfb-observations') ?>"><?= $e($label) ?></a> <?php endforeach ?>
    </div><?php endif ?>
    <div class="table-responsive"><table class="table table-striped"><thead><tr><th>IP</th><th>Classificação</th><th>Descrição</th><th>Confiança</th><th>Evento / análise</th><th>Evidências</th></tr></thead><tbody>
    <?php foreach(($observations??[]) as $s): ?>
    <tr><td><?= $e($s['ip']) ?></td><td><?= $e($s['classification']) ?><?php if(!empty($s['vector_review'])): ?><br><span class="label label-warning">Vetor para triagem</span><?php endif ?></td><td><?= $e($s['threat']) ?></td><td><?= (int)$s['confidence'] ?>%</td><td><?= $e($s['event_at']??'Evento não comprovado') ?><br><small><?= $e($s['recency']??'') ?> — análise: <?= $e($s['created_at']) ?></small></td><td><details><summary>Consultar</summary><pre><?= $e(json_encode($s['evidence']??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre></details></td></tr>
    <?php endforeach ?>
    </tbody></table></div>
    <div class="panel-footer">Página <?= (int)($observations_page??1) ?> de <?= (int)($observations_pages??1) ?>
    <?php if(($observations_page??1)>1): ?><a class="btn btn-default btn-xs" href="<?= $e($modulelink.'&action=ai&decision_view='.$decision_view.'&observation_scope='.($observation_scope??'all').'&observations_page='.($observations_page-1).'#amsfb-observations') ?>">Anterior</a><?php endif ?>
    <?php if(($observations_page??1)<($observations_pages??1)): ?><a class="btn btn-default btn-xs" href="<?= $e($modulelink.'&action=ai&decision_view='.$decision_view.'&observation_scope='.($observation_scope??'all').'&observations_page='.($observations_page+1).'#amsfb-observations') ?>">Próxima</a><?php endif ?>
    </div>
</div>
</div>
<?php if(isset($dashboard['learning'])): $learning=$dashboard['learning'];$learning_scope=$learning_scope??'review';
    $learningLabels=['all'=>'Todos','pending'=>'Pendentes','criteria'=>'Critérios insuficientes','review'=>'Revisão técnica','completed'=>'Concluídos'];
    $learningReasons=['promotion_queued'=>'Aguardando ciclo automático','promotion_threshold'=>'Evidências ou IPs distintos insuficientes para generalizar a regra',
        'existing_rule_review'=>'Regra existente exige revisão individual','filter_branch'=>'Expressão sem comprovação individual',
        'update_daily_limit'=>'Limite diário de atualização atingido','daily_limit'=>'Limite diário de criação atingido','update_cooldown'=>'Aguardando intervalo de atualização']; ?>
<div class="tab-pane" id="amsfb-learning"><div class="panel panel-default">
    <div class="panel-heading"><strong>Aprendizado de regras — não são decisões de bloqueio</strong></div>
    <div class="panel-body">
        <p>Resultados registrados por decisão. Critérios insuficientes não são falhas técnicas. Consultar esta lista não reativa quarentena, não reenfileira histórico, não chama IA e não bane IPs.</p>
        <?php foreach($learningLabels as $scope=>$label): ?><a class="btn btn-xs <?= $scope===$learning_scope?'btn-primary':'btn-default' ?>" href="<?= $e($modulelink.'&action=ai&decision_view='.$decision_view.'&learning_scope='.$scope.'#amsfb-learning') ?>"><?= $e($label) ?> (<?= (int)$learning['counts'][$scope] ?>)</a> <?php endforeach ?>
    </div>
    <div class="table-responsive"><table class="table table-striped"><thead><tr><th>Decisão / IP</th><th>Resultado do aprendizado</th><th>Motivo</th><th>Data da decisão</th><th>Evidências</th></tr></thead><tbody>
    <?php foreach($learning['data'] as $item): ?><tr><td>#<?= (int)$item['id'] ?><br><?= $e($item['ip']) ?></td><td><?= $e($learningLabels[$item['learning_group']]??$item['learning_group']) ?></td><td><?= $e($learningReasons[$item['code']]??$item['code']) ?><?php if($item['retry_at']): ?><br><small>Próxima tentativa a partir de <?= $e(date('d/m/Y H:i:s',(int)$item['retry_at'])) ?></small><?php endif ?></td><td><?= $e($item['updated_at']) ?></td><td><details><summary>Consultar</summary><pre><?= $e(json_encode($item['evidence'],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre></details></td></tr><?php endforeach ?>
    <?php if(!$learning['data']): ?><tr><td colspan="5">Nenhum resultado nesta categoria.</td></tr><?php endif ?>
    </tbody></table></div>
    <div class="panel-footer">Página <?= (int)$learning['page'] ?> de <?= (int)$learning['pages'] ?> — <?= (int)$learning['total'] ?> resultados
    <?php foreach([-1=>'Anterior',1=>'Próxima'] as $step=>$label): $page=$learning['page']+$step;if($page<1||$page>$learning['pages'])continue; ?><a class="btn btn-default btn-xs" href="<?= $e($modulelink.'&action=ai&decision_view='.$decision_view.'&learning_scope='.$learning_scope.'&learning_page='.$page.'#amsfb-learning') ?>"><?= $e($label) ?></a><?php endforeach ?>
    </div>
</div></div><?php endif ?>
<div class="tab-pane" id="amsfb-history">
<div class="panel panel-default" style="margin-top:24px;">
    <div class="panel-heading"><strong>&#128202; Histórico de Sugestões</strong></div>
    <div class="panel-body">
        <!-- Filtros -->
        <form method="get" class="form-inline amsfb-filter-form">
            <input type="hidden" name="module" value="amssoft_fail2ban">
            <input type="hidden" name="action" value="ai">

            <div class="form-group" style="margin-right:8px;">
                <label>Status&nbsp;</label>
                <select name="filter_status" class="form-control form-control-sm">
                    <option value="">Todos</option>
                    <?php foreach ($statusLabels as $val => $info): ?>
                    <option value="<?= $e($val) ?>" <?= ($filters['status'] === $val ? 'selected' : '') ?>><?= $e($info['label']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group" style="margin-right:8px;">
                <label>Severidade&nbsp;</label>
                <select name="filter_severity" class="form-control form-control-sm">
                    <option value="">Todas</option>
                    <?php foreach ($severityLabels as $val => $info): ?>
                    <option value="<?= $e($val) ?>" <?= ($filters['severity'] === $val ? 'selected' : '') ?>><?= $e($info['label']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group" style="margin-right:8px;">
                <label>De&nbsp;</label>
                <input type="date" name="date_from" class="form-control form-control-sm" value="<?= $e($filters['date_from'] ?? '') ?>">
            </div>

            <div class="form-group" style="margin-right:8px;">
                <label>Até&nbsp;</label>
                <input type="date" name="date_to" class="form-control form-control-sm" value="<?= $e($filters['date_to'] ?? '') ?>">
            </div>

            <button type="submit" class="btn btn-sm btn-primary">Filtrar</button>
            <a href="<?= $e($modulelink . '&action=ai') ?>" class="btn btn-sm btn-default">Limpar</a>
        </form>
    </div>

    <?php if (empty($history)): ?>
    <div class="panel-body text-muted">Nenhum histórico encontrado.</div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-striped amsfb-table amsfb-table-sm">
            <thead>
                <tr>
                    <th>#</th>
                    <th>IP</th>
                    <th>Ameaça</th>
                    <th>Severidade</th>
                    <th>Confiança</th>
                    <th>Status</th>
                    <th>Criado em</th>
                    <th>Resolvido em</th>
                    <th>Ações</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($history as $s): ?>
                <tr>
                    <td><?= (int)$s['id'] ?></td>
                    <td>
                        <?= $e($s['ip']) ?>
                        <?php if (!empty($geo_data[$s['ip']])): ?>
                        <br><small class="amsfb-geo-info"><?= $e(\AMS\Fail2Ban\GeoIP::formatGeo($geo_data[$s['ip']])) ?></small>
                        <?php endif; ?>
                    </td>
                    <td><?= $e($s['threat']) ?></td>
                    <td>
                        <span class="<?= $e($severityLabels[$s['severity']]['class'] ?? 'amsfb-sev-medium') ?>">
                            <?= $e($severityLabels[$s['severity']]['label'] ?? $s['severity']) ?>
                        </span>
                    </td>
                    <td><?= (int)$s['confidence'] ?>%</td>
                    <td>
                        <span class="label <?= $e($statusLabels[$s['status']]['class'] ?? 'label-default') ?>">
                            <?= $e($statusLabels[$s['status']]['label'] ?? $s['status']) ?>
                        </span>
                    </td>
                    <td><?= $e($s['created_at']  ?? '-') ?></td>
                    <td><?= $e($s['resolved_at'] ?? '-') ?></td>
                    <td>
                        <button class="btn btn-xs btn-info amsfb-evidence-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                data-evidence="<?= $e(json_encode($s['evidence'] ?? [])) ?>"
                                title="Ver evidências">
                            &#128220; Evidências
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Paginação do histórico -->
    <?php if ($history_pages > 1): ?>
    <div class="amsfb-pagination-wrap">
        <nav aria-label="Paginação histórico">
            <ul class="pagination pagination-sm">
                <?php if ($history_page > 1): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&history_page=' . ($history_page - 1)
                        . '&filter_status='   . urlencode($filters['status'])
                        . '&filter_severity=' . urlencode($filters['severity'])
                        . '&date_from='       . urlencode($filters['date_from'])
                        . '&date_to='         . urlencode($filters['date_to'])
                    ) ?>">&laquo;</a>
                </li>
                <?php endif; ?>

                <?php
                $hStart = max(1, $history_page - 3);
                $hEnd   = min($history_pages, $history_page + 3);
                for ($p = $hStart; $p <= $hEnd; $p++):
                ?>
                <li class="<?= $p === $history_page ? 'active' : '' ?>">
                    <a href="<?= $e($modulelink . '&action=ai&history_page=' . $p
                        . '&filter_status='   . urlencode($filters['status'])
                        . '&filter_severity=' . urlencode($filters['severity'])
                        . '&date_from='       . urlencode($filters['date_from'])
                        . '&date_to='         . urlencode($filters['date_to'])
                    ) ?>"><?= $p ?></a>
                </li>
                <?php endfor; ?>

                <?php if ($history_page < $history_pages): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&history_page=' . ($history_page + 1)
                        . '&filter_status='   . urlencode($filters['status'])
                        . '&filter_severity=' . urlencode($filters['severity'])
                        . '&date_from='       . urlencode($filters['date_from'])
                        . '&date_to='         . urlencode($filters['date_to'])
                    ) ?>">&raquo;</a>
                </li>
                <?php endif; ?>
            </ul>
        </nav>
        <p class="text-muted amsfb-pagination-info">
            <?= (int)$history_total ?> registro(s) &mdash; página <?= (int)$history_page ?> de <?= (int)$history_pages ?>
        </p>
    </div>
    <?php endif; ?>

    <?php endif; ?>
</div>

<!-- =========================================================
     Modal: Evidências
     ========================================================= -->
</div></div>
<script>
document.addEventListener('DOMContentLoaded', function () {
    var originalPost=window.AMSFB&&window.AMSFB.post;
    if(originalPost)window.AMSFB.post=function(action,operation,params,callback){
        return originalPost.call(this,action,operation,params,function(data){
            callback(data);
            if(action==='ai'&&data.success&&['approve','reject','bulk_approve_ids','bulk_reject_ids','create_filter'].indexOf(operation)>=0)location.reload();
        });
    };
    var links = document.querySelectorAll('#amsfb-ai-tabs a[href^="#amsfb-"]');
    function activate(id) {
        document.querySelectorAll('#amsfb-ai-tabs > li').forEach(function(li){li.classList.remove('active');});
        document.querySelectorAll('#amsfb-decisions, #amsfb-observations, #amsfb-learning, #amsfb-history').forEach(function(pane){pane.classList.toggle('active','#'+pane.id===id);});
        links.forEach(function (a) {
            var pane = document.querySelector(a.getAttribute('href'));
            if (pane) pane.classList.toggle('active', a.getAttribute('href') === id);
            a.parentNode.classList.toggle('active', a.getAttribute('href') === id);
        });
    }
    links.forEach(function (a) { a.addEventListener('click', function (event) {event.preventDefault();activate(a.getAttribute('href'));}); });
    if (location.hash === '#amsfb-learning' || location.search.indexOf('learning_page=') >= 0 || location.search.indexOf('learning_scope=') >= 0) activate('#amsfb-learning');
    else if (location.hash === '#amsfb-observations' || location.search.indexOf('observations_page=') >= 0) activate('#amsfb-observations');
    else if (location.search.indexOf('history_page=') >= 0 || location.search.indexOf('filter_status=') >= 0) activate('#amsfb-history');
});
</script>
<div class="modal fade" id="amsfb-evidence-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">Evidências do log</h4>
            </div>
            <div class="modal-body">
                <pre id="amsfb-evidence-content" class="amsfb-modal-pre"></pre>
            </div>
        </div>
    </div>
</div>

<!-- =========================================================
     Modal: Regra sugerida
     ========================================================= -->
<div class="modal fade" id="amsfb-rule-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">Regra sugerida (jail.local)</h4>
            </div>
            <div class="modal-body">
                <pre id="amsfb-rule-content" class="amsfb-modal-pre"></pre>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // Helpers: country card sync
    // -------------------------------------------------------------------------

    /**
     * Decrementa o badge de contagem de um card de país e remove o card se
     * a contagem chegar a 0. Se o painel ficar sem nenhum card, esconde o
     * painel inteiro.
     *
     * Decisão de design: atualização via textContent decremental (sem AJAX
     * re-fetch). O valor inicial vem do PHP via getPendingGroupedByCountry()
     * e é decrementado localmente a cada ação (individual ou bulk). Isso
     * evita requests extras ao servidor. A consistência é garantida porque
     * cada linha removida da tabela corresponde exatamente a um decremento.
     */
    function updateCountryCard(countryCode, delta) {
        var cards = document.querySelectorAll('.amsfb-country-card');
        for (var i = 0; i < cards.length; i++) {
            var card = cards[i];
            if (card.getAttribute('data-country-code') === countryCode) {
                var countEl = card.querySelector('.amsfb-country-count');
                if (!countEl) break;
                var current = parseInt(countEl.textContent, 10) || 0;
                var next = current + delta;
                if (next <= 0) {
                    card.remove();
                    // Esconder painel se não restam cards
                    var remaining = document.querySelectorAll('.amsfb-country-card');
                    if (remaining.length === 0) {
                        var panel = document.querySelector('.amsfb-country-panel');
                        if (panel) panel.style.display = 'none';
                    }
                } else {
                    countEl.textContent = next;
                }
                break;
            }
        }
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // -------------------------------------------------------------------------
    // Approve
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-approve-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = this.getAttribute('data-id');
            if (!confirm('Aprovar sugestão #' + id + ' e executar ban?')) return;

            this.disabled = true;
            var self = this;

            window.AMSFB.post('ai', 'approve', { id: id }, function (data) {
                if (data.success) {
                    var row = document.getElementById('amsfb-row-' + id);
                    var cc = row ? row.getAttribute('data-country-code') : '';
                    if (row) {
                        updateCountryCard(cc, -1);
                        row.remove();
                    }
                    // Remover duplicatas do mesmo IP dispensadas automaticamente
                    if (Array.isArray(data.dismissed_ids)) {
                        data.dismissed_ids.forEach(function (did) {
                            var dup = document.getElementById('amsfb-row-' + did);
                            if (dup) {
                                var dupCc = dup.getAttribute('data-country-code');
                                updateCountryCard(dupCc, -1);
                                dup.remove();
                            }
                        });
                    }
                    alert('✓ ' + (data.message || 'Aprovado.'));
                } else {
                    self.disabled = false;
                    alert('✗ ' + (data.error || 'Erro ao aprovar.'));
                }
            });
        });
    });

    // -------------------------------------------------------------------------
    // Reject
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-reject-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = this.getAttribute('data-id');
            if (!confirm('Rejeitar sugestão #' + id + '?')) return;

            this.disabled = true;
            var self = this;

            window.AMSFB.post('ai', 'reject', { id: id }, function (data) {
                if (data.success) {
                    var row = document.getElementById('amsfb-row-' + id);
                    if (row) {
                        var cc = row.getAttribute('data-country-code');
                        updateCountryCard(cc, -1);
                        row.remove();
                    }
                } else {
                    self.disabled = false;
                    alert('✗ ' + (data.error || 'Erro ao rejeitar.'));
                }
            });
        });
    });

    // -------------------------------------------------------------------------
    // Criar Filtro
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-create-filter-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id         = this.getAttribute('data-id');
            var filterName = this.getAttribute('data-filter-name');
            var hasRegex   = this.getAttribute('data-has-regex') === '1';
            var failregex  = this.getAttribute('data-failregex');
            var self       = this;

            var msg;
            if (hasRegex) {
                msg = 'Criar filtro fail2ban para o padrão de ataque detectado?\n\n'
                    + 'Filtro: amsfb-' + filterName + '\n'
                    + 'Jail:   amsfb-' + filterName + '\n'
                    + 'Regex:  ' + failregex + '\n\n'
                    + 'Isso NÃO bane nenhum IP agora.\n'
                    + 'IPs que realizarem este padrão no futuro serão banidos\n'
                    + 'automaticamente pelo fail2ban sem intervenção manual.';
            } else {
                msg = 'A IA irá analisar as evidências desta sugestão e gerar\n'
                    + 'automaticamente um failregex para bloquear este padrão de ataque.\n\n'
                    + 'Isso NÃO bane nenhum IP agora.\n'
                    + 'Deseja continuar?';
            }

            msg='Solicitar aprendizado? O cron busca reutilizar ou ampliar a proteção antes de criar outra. Não há chamada extra à IA nem reativação automática de quarentenas.';
            if (!confirm(msg)) return;

            self.disabled = true;
            self.innerHTML = 'Solicitando...';

            window.AMSFB.post('ai', 'create_filter', { id: id }, function (data) {
                if (data.success && data.queued) { self.innerHTML = 'Aprendizado solicitado'; self.disabled = true; alert(data.message); return; }
                if (data.success) {
                    self.innerHTML = '&#10003; Filtro criado';
                    self.disabled  = true;
                    self.classList.remove('btn-default');
                    self.classList.add('btn-success');
                    // Atualizar data-has-regex e data-filter-name se IA gerou
                    if (data.generated_by_ai && data.failregex) {
                        self.setAttribute('data-has-regex', '1');
                        self.setAttribute('data-filter-name', data.filter_name || '');
                        self.setAttribute('data-failregex', data.failregex || '');
                        // Atualizar coluna Filtro na mesma linha
                        var row = document.getElementById('amsfb-row-' + id);
                        if (row) {
                            var filterCell = row.querySelector('td:nth-child(6)');
                            if (filterCell) {
                                filterCell.innerHTML = '<code style="font-size:11px;" title="failregex: '
                                    + data.failregex.replace(/"/g, '&quot;')
                                    + '">amsfb-' + (data.filter_name || '') + '</code>'
                                    + '<br><small class="text-success">&#10003; criado</small>';
                            }
                        }
                    } else {
                        // Atualizar indicador "criado" na coluna Filtro
                        var row2 = document.getElementById('amsfb-row-' + id);
                        if (row2) {
                            var filterCell2 = row2.querySelector('td:nth-child(6) small');
                            if (!filterCell2) {
                                var codeEl = row2.querySelector('td:nth-child(6) code');
                                if (codeEl) {
                                    codeEl.insertAdjacentHTML('afterend',
                                        '<br><small class="text-success">&#10003; criado</small>');
                                }
                            }
                        }
                    }
                    // Linha permanece na tabela — o IP ainda pode ser banido
                    alert('✓ ' + (data.message || 'Filtro criado com sucesso.'));
                } else if (data.similar_to) {
                    // Filtro similar encontrado — perguntar ao admin
                    var simPct = Math.round((data.similarity || 0) * 100);
                    var confirmMsg = '⚠️ Filtro similar encontrado!\n\n'
                        + 'Filtro existente: amsfb-' + data.similar_to + '\n'
                        + 'Similaridade: ' + simPct + '%\n'
                        + 'Novo filtro: amsfb-' + (data.filter_name || filterName) + '\n\n'
                        + 'Deseja criar um novo filtro mesmo assim?\n'
                        + '(Selecione "Cancelar" para usar o filtro existente)';
                    if (confirm(confirmMsg)) {
                        // Reenviar com force=1
                        self.innerHTML = '&#8987; Criando...';
                        self.disabled = true;
                        window.AMSFB.post('ai', 'create_filter', { id: id, force: 1 }, function (data2) {
                            if (data2.success) {
                                self.innerHTML = '&#10003; Filtro criado';
                                self.disabled = true;
                                self.classList.remove('btn-default');
                                self.classList.add('btn-success');
                                alert('✓ ' + (data2.message || 'Filtro criado com sucesso.'));
                            } else {
                                self.disabled = false;
                                self.innerHTML = '&#128736; Criar Filtro';
                                alert('✗ ' + (data2.error || 'Erro ao criar filtro.'));
                            }
                        });
                    } else {
                        self.disabled = false;
                        self.innerHTML = '&#128736; Criar Filtro';
                    }
                } else {
                    self.disabled  = false;
                    self.innerHTML = hasRegex ? '&#128736; Criar Filtro' : '&#128736; Criar Filtro';
                    alert('✗ ' + (data.error || 'Erro ao criar filtro.'));
                }
            });
        });
    });

    // -------------------------------------------------------------------------
    // Evidence modal
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-evidence-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var rawEvidence = this.getAttribute('data-evidence');
            var lines = [];
            try { lines = JSON.parse(rawEvidence); } catch (e) { lines = [rawEvidence]; }
            var content = document.getElementById('amsfb-evidence-content');
            if (content) content.textContent = Array.isArray(lines) ? lines.join('\n') : String(lines);
            if (typeof $ !== 'undefined') $('#amsfb-evidence-modal').modal('show');
        });
    });

    // -------------------------------------------------------------------------
    // Rule modal
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-rule-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var rule    = this.getAttribute('data-rule');
            var content = document.getElementById('amsfb-rule-content');
            if (content) content.textContent = rule;
            if (typeof $ !== 'undefined') $('#amsfb-rule-modal').modal('show');
        });
    });

    // -------------------------------------------------------------------------
    // Analisar agora — sequencial com progresso
    // -------------------------------------------------------------------------
    var runNowBtn = document.getElementById('amsfb-run-now-btn');
    var currentAiMode = '<?= $e($ai_mode ?? 'suggestion') ?>';
    if (runNowBtn) {
        runNowBtn.addEventListener('click', function () {
            var confirmMsg = 'Rodar análise de IA agora em todos os logs configurados?';
            if (currentAiMode === 'auto' || currentAiMode === 'threshold') {
                confirmMsg += '\n\n⚠️ Modo automático ativo — a análise manual sempre gera sugestões pendentes para revisão.';
                confirmMsg += '\nBans automáticos ocorrem apenas via cron.';
            }
            if (!confirm(confirmMsg)) return;
            runNowBtn.disabled = true;

            // 1. Buscar lista de logs (com retry CSRF)
            runNowBtn.innerHTML = '&#9203; Buscando logs...';
            function doListLogs(_csrfRetried) {
                window.AMSFB.post('ai', 'list_logs', {}, function (data) {
                    // Retry once on CSRF failure (token may have been rotated)
                    if (!data.success && data.error && data.error.indexOf('CSRF') !== -1 && !_csrfRetried) {
                        doListLogs(true);
                        return;
                    }
                    if (!data.success || !data.logs || data.logs.length === 0) {
                        runNowBtn.disabled = false;
                        runNowBtn.innerHTML = '&#9654; Analisar agora';
                        alert(data.error || 'Nenhum log encontrado para análise.');
                        return;
                    }

                var logs = data.logs;
                var total = logs.length;
                var current = 0;
                var totalSaved = 0;
                var totalSkipped = 0;
                var totalFiltered = 0;
                var failedLogs = [];
                var truncatedLogs = [];
                var cancelLoop = false; // botão "Parar"
                var totalBatches = 0;  // contagem total de lotes processados
                var pendingTbody = document.getElementById('amsfb-pending-tbody');
                var badge = document.querySelector('.panel-heading .badge');

                // Delay adaptativo entre requests: começa em 500ms, aumenta em caso de 429
                var baseDelay = 500;
                var currentDelay = baseDelay;
                var MAX_DELAY = 30000; // max 30s (backoff máximo)

                // Botão Parar
                var stopBtn = document.getElementById('amsfb-stop-btn');
                if (stopBtn) {
                    stopBtn.style.display = 'inline-block';
                    stopBtn.addEventListener('click', function () {
                        cancelLoop = true;
                        stopBtn.disabled = true;
                        stopBtn.innerHTML = '&#9208; Parando...';
                    });
                }

                // 2. Analisar cada log sequencialmente (com loop de batch por log)
                function analyzeNext() {
                    // Verificar cancelamento
                    if (cancelLoop) {
                        runNowBtn.disabled = false;
                        runNowBtn.innerHTML = '&#9654; Analisar agora';
                        if (stopBtn) { stopBtn.style.display = 'none'; stopBtn.disabled = false; stopBtn.innerHTML = '&#9726; Parar'; }
                        var msg = '⏹ Análise interrompida pelo usuário.';
                        if (totalBatches > 0) msg += '\n' + totalBatches + ' lote(s) processado(s) antes de parar.';
                        if (totalSaved > 0) msg += '\n' + totalSaved + ' sugestão(ões) encontrada(s).';
                        alert(msg);
                        location.reload();
                        return;
                    }

                    if (current >= logs.length) {
                        // Finalizado
                        runNowBtn.disabled = false;
                        runNowBtn.innerHTML = '&#9654; Analisar agora';
                        if (stopBtn) { stopBtn.style.display = 'none'; stopBtn.disabled = false; stopBtn.innerHTML = '&#9726; Parar'; }
                        var analyzed = total - totalSkipped - totalFiltered - failedLogs.length;
                        var msg = '✓ Análise concluída — ' + analyzed + ' log(s) analisado(s)';
                        if (totalBatches > 1) {
                            msg += ' (' + totalBatches + ' lotes processados)';
                        }
                        if (totalSkipped > 0) {
                            msg += ', ' + totalSkipped + ' pulado(s) (sem dados novos)';
                        }
                        if (totalFiltered > 0) {
                            msg += ', ' + totalFiltered + ' filtrado(s) (apenas IPs whitelisted/banidos)';
                        }
                        if (failedLogs.length > 0) {
                            msg += ', ' + failedLogs.length + ' FALHARAM';
                            msg += '\n\nLogs que falharam:\n';
                            failedLogs.forEach(function (f) { msg += '• ' + (f.label || f.path) + ' (' + f.reason + ')\n'; });
                            msg += '\nClique em "Analisar agora" novamente para tentar novamente';
                            msg += '\n(estes logs serão reprocessados pois o watermark não foi atualizado).';
                        }
                        if (truncatedLogs.length > 0) {
                            msg += '\n\n⚠ ' + truncatedLogs.length + ' log(s) tiveram resposta truncada pela IA.';
                            msg += '\nAlgumas sugestões podem ter sido perdidas.';
                        }
                        if (totalSaved > 0) {
                            msg += '\n\n' + totalSaved + ' sugestão(ões) encontrada(s).';
                        } else if (analyzed === 0 && failedLogs.length === 0) {
                            msg += '\n\nNenhum log com conteúdo novo — todos os logs já foram analisados.';
                        } else if (failedLogs.length === 0) {
                            msg += '. Nenhuma classificação nova salva; consulte a elegibilidade e as proteções.';
                        }
                        if (currentAiMode === 'auto' || currentAiMode === 'threshold') {
                            msg += '\n\n⚠️ Modo automático ativo — estas sugestões foram salvas como pendentes para sua revisão.';
                            msg += '\nA IA bloqueia pelo cron; o Fail2Ban atua continuamente, sem esperar a IA.';
                        }
                        alert(msg);
                        location.reload();
                        return;
                    }

                    var log = logs[current];
                    current++;

                    // Skip client-side: log sem conteúdo novo (watermark em dia).
                    if (log.has_new === false) {
                        totalSkipped++;
                        runNowBtn.innerHTML = '&#9203; Pulando: ' + (log.label || log.path) + ' (' + current + '/' + total + ')...';
                        setTimeout(analyzeNext, 20);
                        return;
                    }

                    // Iniciar loop de batch para este log (sem token na primeira chamada)
                    analyzeLogLoop(log, 0, '');
                }

                // Loop de batch: analisa um log repetidamente enquanto has_more=true
                // batchToken: token da sessão anterior (vazio na primeira chamada)
                function analyzeLogLoop(log, batchNum, batchToken) {
                    if (cancelLoop) {
                        setTimeout(analyzeNext, 20);
                        return;
                    }

                    batchNum = batchNum || 1;
                    var batchLabel = batchNum > 1 ? ' (lote ' + batchNum + ')' : '';
                    runNowBtn.innerHTML = '&#9203; Analisando: ' + (log.label || log.path) + batchLabel + ' (' + current + '/' + total + ')...';

                    // Enviar batch_token para identificação de continuação
                    var postData = { path: log.path };
                    if (batchToken) postData.batch_token = batchToken;

                    function doAnalyzeLog(_csrfRetried) {
                    window.AMSFB.post('ai', 'analyze_log', postData, function (result) {
                        // Retry once on CSRF failure
                        if (!result.success && result.error && result.error.indexOf('CSRF') !== -1 && !_csrfRetried) {
                            doAnalyzeLog(true);
                            return;
                        }

                        // Session active (outro processo está analisando este log)
                        if (!result.success && result.error === 'session_active') {
                            // Mostrar banner amigável em vez de erro crua
                            var banner = document.createElement('div');
                            banner.className = 'alert alert-warning';
                            banner.style.cssText = 'position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:9999;max-width:600px;box-shadow:0 2px 10px rgba(0,0,0,0.2);';
                            banner.innerHTML = '<strong>&#9208; Análise já em andamento</strong><br>' + escapeHtml(result.error_msg || 'Outro processo está analisando este log.') + '<br><small>Aguarde a conclusão ou recarregue a página.</small>';
                            document.body.appendChild(banner);
                            setTimeout(function () { banner.remove(); }, 10000);
                            // Pular para próximo log
                            setTimeout(analyzeNext, currentDelay);
                            return;
                        }

                        // Erros que impediram o processamento
                        if (!result.success) {
                            var reason = result.error_msg || result.error || 'Erro desconhecido';
                            var delayMs = currentDelay;
                            if (result.error === 'rate_limited') {
                                reason = 'Rate limit do provedor';
                                delayMs = (result.retry_after || 60) * 1000;
                            }
                            failedLogs.push({ path: log.path, label: log.label || log.path, reason: reason });

                            // Countdown visual durante pausa de 429
                            if (result.error === 'rate_limited') {
                                var remaining = Math.ceil(delayMs / 1000);
                                runNowBtn.innerHTML = '&#9208; Rate limit — aguardando ' + remaining + 's...';
                                var countdown = setInterval(function () {
                                    remaining--;
                                    if (remaining <= 0) {
                                        clearInterval(countdown);
                                        runNowBtn.innerHTML = '&#9203; Retomando análise...';
                                    } else {
                                        runNowBtn.innerHTML = '&#9208; Rate limit — aguardando ' + remaining + 's...';
                                    }
                                }, 1000);
                            }

                            // Em caso de erro, pular para próximo log (não encadear no mesmo)
                            setTimeout(analyzeNext, delayMs);
                            return;
                        }

                        // Sucesso: resetar delay para base
                        currentDelay = baseDelay;
                        totalBatches++;

                        // Log filtrado ou pulado
                        if (result.filtered) {
                            totalFiltered++;
                        } else if (result.message) {
                            totalSkipped++;
                        }

                        // Parse failure / truncamento
                        if (result.truncated) {
                            truncatedLogs.push(log.path);
                        }

                        // Adicionar sugestões na tabela (mesmo código anterior)
                        if (result.success && result.suggestions && result.suggestions.length > 0) {
                            totalSaved += result.saved;

                            result.suggestions.forEach(function (s) {
                                if ((s.classification || s.action || 'ban') !== 'ban') return;
                                if (!pendingTbody) return;
                                if (document.getElementById('amsfb-row-' + s.id)) return;

                                var tr = document.createElement('tr');
                                tr.id = 'amsfb-row-' + s.id;
                                tr.setAttribute('data-country-code', '');

                                var actionHtml = '<button class="btn btn-xs btn-success amsfb-approve-btn" data-id="' + s.id + '" title="Banir este IP">&#128683; Banir IP</button> '
                                    + '<button class="btn btn-xs btn-danger amsfb-reject-btn" data-id="' + s.id + '" title="Rejeitar sugestão">&#10007; Rejeitar</button> '
                                    + '<button class="btn btn-xs btn-info amsfb-evidence-btn" data-id="' + s.id + '" data-evidence="' + escapeHtml(JSON.stringify(s.evidence || [])) + '" title="Ver evidências">&#128220; Evidências</button> ';

                                if (s.suggested_rule) {
                                    actionHtml += '<button class="btn btn-xs btn-warning amsfb-rule-btn" data-id="' + s.id + '" data-rule="' + escapeHtml(s.suggested_rule) + '" title="Ver regra sugerida">&#128196; Regra</button> ';
                                }

                                if (s.failregex || (s.evidence && s.evidence.length > 0)) {
                                    actionHtml += '<button class="btn btn-xs btn-default amsfb-create-filter-btn" data-id="' + s.id + '" data-filter-name="' + escapeHtml(s.filter_name || '') + '" data-has-regex="' + (s.failregex ? '1' : '0') + '" data-failregex="' + escapeHtml(s.failregex || '') + '" title="Criar filtro fail2ban">&#128736; Criar Filtro</button>';
                                }

                                tr.innerHTML =
                                    '<td><input type="checkbox" class="amsfb-row-cb" data-id="' + s.id + '"></td>'
                                    + '<td><strong>' + escapeHtml(s.ip || '') + '</strong></td>'
                                    + '<td>' + escapeHtml(s.threat || '') + '</td>'
                                    + '<td><span class="amsfb-sev-' + escapeHtml(s.severity || 'medium') + '">'
                                    + escapeHtml(s.severity || 'medium') + '</span></td>'
                                    + '<td><div class="amsfb-confidence-bar">'
                                    + '<div class="amsfb-confidence-fill" style="width:' + (s.confidence || 0) + '%"></div>'
                                    + '<span>' + (s.confidence || 0) + '%</span></div></td>'
                                    + '<td>' + escapeHtml(s.jail || '-') + '</td>'
                                    + '<td>' + (s.filter_name ? '<code style="font-size:11px;">amsfb-' + escapeHtml(s.filter_name) + '</code>' : '-')
                                    + '</td>'
                                    + '<td>' + (s.bantime ? escapeHtml(String(s.bantime)) + 's' : '-') + '</td>'
                                    + '<td>' + escapeHtml(s.created_at || '-') + '</td>'
                                    + '<td class="amsfb-action-btns">' + actionHtml + '</td>';

                                if (pendingTbody.firstChild) {
                                    pendingTbody.insertBefore(tr, pendingTbody.firstChild);
                                } else {
                                    pendingTbody.appendChild(tr);
                                }

                                bindAllHandlers(tr);
                            });

                            if (badge) {
                                var count = pendingTbody.querySelectorAll('tr').length;
                                badge.textContent = count;
                            }
                        }

                        // Verificar se há mais conteúdo (has_more)
                        if (result.has_more && !cancelLoop) {
                            // Encadear no mesmo log — progresso visual
                            var nextBatch = batchNum + 1;
                            var batchesInfo = result.batches_done ? ' (lote ' + result.batches_done + '/' + result.batch_limit + ')' : '';
                            runNowBtn.innerHTML = '&#9203; ' + (log.label || log.path) + batchesInfo + ' — mais conteúdo pendente...';
                            setTimeout(function () { analyzeLogLoop(log, nextBatch, result.batch_token || ''); }, currentDelay);
                        } else {
                            // Log esgotou ou teto atingido — próximo log
                            if (result.batch_limit_reached) {
                                // Mostrar aviso de teto
                                var tetoMsg = 'Teto de ' + result.batch_limit + ' lotes atingido para ' + (log.label || log.path) + '.';
                                tetoMsg += ' Restante será processado na próxima análise.';
                                // Usar console em vez de alert para não interromper o fluxo
                                console.warn('[AMSFB] ' + tetoMsg);
                            }
                            setTimeout(analyzeNext, currentDelay);
                        }
                    });
                    }
                    doAnalyzeLog(false);
                }

                function escapeHtml(str) {
                    var div = document.createElement('div');
                    div.textContent = str;
                    return div.innerHTML;
                }

                function bindAllHandlers(row) {
                    // Banir IP
                    var approveBtn = row.querySelector('.amsfb-approve-btn');
                    if (approveBtn) {
                        approveBtn.addEventListener('click', function () {
                            var id = this.getAttribute('data-id');
                            if (!confirm('Aprovar sugestão #' + id + ' e executar ban?')) return;
                            this.disabled = true;
                            var self = this;
                            window.AMSFB.post('ai', 'approve', { id: id }, function (data) {
                                if (data.success) {
                                    var cc = row.getAttribute('data-country-code');
                                    updateCountryCard(cc, -1);
                                    row.remove();
                                    if (badge) badge.textContent = pendingTbody.querySelectorAll('tr').length;
                                    alert('✓ ' + (data.message || 'Aprovado.'));
                                } else {
                                    self.disabled = false;
                                    alert('✗ ' + (data.error || 'Erro ao aprovar.'));
                                }
                            });
                        });
                    }

                    // Rejeitar
                    var rejectBtn = row.querySelector('.amsfb-reject-btn');
                    if (rejectBtn) {
                        rejectBtn.addEventListener('click', function () {
                            var id = this.getAttribute('data-id');
                            if (!confirm('Rejeitar sugestão #' + id + '?')) return;
                            this.disabled = true;
                            var self = this;
                            window.AMSFB.post('ai', 'reject', { id: id }, function (data) {
                                if (data.success) {
                                    var cc = row.getAttribute('data-country-code');
                                    updateCountryCard(cc, -1);
                                    row.remove();
                                    if (badge) badge.textContent = pendingTbody.querySelectorAll('tr').length;
                                } else {
                                    self.disabled = false;
                                    alert('✗ ' + (data.error || 'Erro ao rejeitar.'));
                                }
                            });
                        });
                    }

                    // Evidências
                    var evidenceBtn = row.querySelector('.amsfb-evidence-btn');
                    if (evidenceBtn) {
                        evidenceBtn.addEventListener('click', function () {
                            var rawEvidence = this.getAttribute('data-evidence');
                            var lines = [];
                            try { lines = JSON.parse(rawEvidence); } catch (e) { lines = [rawEvidence]; }
                            var content = document.getElementById('amsfb-evidence-content');
                            if (content) content.textContent = Array.isArray(lines) ? lines.join('\n') : String(lines);
                            if (typeof $ !== 'undefined') $('#amsfb-evidence-modal').modal('show');
                        });
                    }

                    // Regra sugerida
                    var ruleBtn = row.querySelector('.amsfb-rule-btn');
                    if (ruleBtn) {
                        ruleBtn.addEventListener('click', function () {
                            var rule = this.getAttribute('data-rule');
                            var content = document.getElementById('amsfb-rule-content');
                            if (content) content.textContent = rule;
                            if (typeof $ !== 'undefined') $('#amsfb-rule-modal').modal('show');
                        });
                    }

                    // Criar Filtro
                    var filterBtn = row.querySelector('.amsfb-create-filter-btn');
                    if (filterBtn) {
                        filterBtn.addEventListener('click', function () {
                            var id = this.getAttribute('data-id');
                            var filterName = this.getAttribute('data-filter-name');
                            var hasRegex = this.getAttribute('data-has-regex') === '1';
                            var failregex = this.getAttribute('data-failregex');
                            var self = this;

                            var msg;
                            if (hasRegex) {
                                msg = 'Criar filtro fail2ban para o padrão de ataque detectado?\n\n'
                                    + 'Filtro: amsfb-' + filterName + '\n'
                                    + 'Regex:  ' + failregex + '\n\n'
                                    + 'Isso NÃO bane nenhum IP agora.';
                            } else {
                                msg = 'A IA irá gerar um failregex a partir das evidências e criar o filtro.\n\n'
                                    + 'Deseja continuar?';
                            }

                            msg='Solicitar aprendizado? O cron busca reutilizar ou ampliar a proteção antes de criar outra. Não há chamada extra à IA nem reativação automática de quarentenas.';
                            if (!confirm(msg)) return;
                            self.disabled = true;
                            self.innerHTML = 'Solicitando...';

                            window.AMSFB.post('ai', 'create_filter', { id: id }, function (data) {
                                if (data.success && data.queued) { self.innerHTML = 'Aprendizado solicitado'; self.disabled = true; alert(data.message); return; }
                                if (data.success) {
                                    self.innerHTML = '&#10003; Filtro criado';
                                    self.disabled = true;
                                    self.classList.remove('btn-default');
                                    self.classList.add('btn-success');
                                    alert('✓ ' + (data.message || 'Filtro criado.'));
                                } else if (data.similar_to) {
                                    var simPct = Math.round((data.similarity || 0) * 100);
                                    var confirmMsg = '⚠️ Filtro similar encontrado!\n\n'
                                        + 'Filtro existente: amsfb-' + data.similar_to + '\n'
                                        + 'Similaridade: ' + simPct + '%\n'
                                        + 'Novo filtro: amsfb-' + (data.filter_name || filterName) + '\n\n'
                                        + 'Deseja criar um novo filtro mesmo assim?';
                                    if (confirm(confirmMsg)) {
                                        self.innerHTML = '&#8987; Criando...';
                                        self.disabled = true;
                                        window.AMSFB.post('ai', 'create_filter', { id: id, force: 1 }, function (data2) {
                                            if (data2.success) {
                                                self.innerHTML = '&#10003; Filtro criado';
                                                self.disabled = true;
                                                self.classList.remove('btn-default');
                                                self.classList.add('btn-success');
                                                alert('✓ ' + (data2.message || 'Filtro criado.'));
                                            } else {
                                                self.disabled = false;
                                                self.innerHTML = '&#128736; Criar Filtro';
                                                alert('✗ ' + (data2.error || 'Erro ao criar filtro.'));
                                            }
                                        });
                                    } else {
                                        self.disabled = false;
                                        self.innerHTML = '&#128736; Criar Filtro';
                                    }
                                } else {
                                    self.disabled = false;
                                    self.innerHTML = '&#128736; Criar Filtro';
                                    alert('✗ ' + (data.error || 'Erro ao criar filtro.'));
                                }
                            });
                        });
                    }
                }

                // Iniciar análise
                analyzeNext();
            });
            }
            doListLogs(false);
        });
    }

    // -------------------------------------------------------------------------
    // Selection Manager: gerencia seleção cross-page por país
    // -------------------------------------------------------------------------
    // FONTE DE VERDADE: selectionByCountry (persistido em sessionStorage).
    // Checkboxes visíveis na página são apenas um reflexo parcial desse estado.
    // Quando o admin navega para outra página (reload), os checkboxes são
    // perdidos, mas o sessionStorage preserva a seleção. Ao carregar a página,
    // re-marcamos os checkboxes cujos IDs estão no sessionStorage.
    //
    // Estrutura: { 'CN': [1,2,3], '': [4,5], ... }
    // Chave '' = grupo "Desconhecido" (sem country_code).
    var STORAGE_KEY = 'amsfb_bulk_attack_selection_v229';
    var selectAllCb = document.getElementById('amsfb-select-all');

    function loadSelection() {
        // Carregar seleção do sessionStorage (sobrevive reload da paginação)
        try {
            var raw = sessionStorage.getItem(STORAGE_KEY);
            if (raw) {
                var parsed = JSON.parse(raw);
                // Converter arrays de volta para objetos com IDs como chaves
                var result = {};
                Object.keys(parsed).forEach(function (cc) {
                    result[cc] = {};
                    parsed[cc].forEach(function (id) { result[cc][id] = true; });
                });
                return result;
            }
        } catch (e) {}
        return {};
    }

    function saveSelection() {
        // Salvar seleção no sessionStorage
        try {
            var serializable = {};
            Object.keys(selectionByCountry).forEach(function (cc) {
                serializable[cc] = Object.keys(selectionByCountry[cc]).map(Number);
            });
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(serializable));
        } catch (e) {}
    }

    // Inicializar: carregar seleção salva + marcar checkboxes visíveis
    var selectionByCountry = loadSelection();

    function syncCheckboxesFromSelection() {
        // Marcar checkboxes visíveis cujos IDs estão no selectionByCountry
        document.querySelectorAll('.amsfb-row-cb').forEach(function (cb) {
            var id = parseInt(cb.getAttribute('data-id'), 10);
            if(cb.disabled){removeIdFromSelection(id);cb.checked=false;return;}
            if (id > 0) {
                var isSelected = Object.keys(selectionByCountry).some(function (cc) {
                    return selectionByCountry[cc][id] === true;
                });
                if (isSelected && !cb.disabled) cb.checked = true;
            }
        });
    }

    // Sync na carga da página (após reload da paginação)
    syncCheckboxesFromSelection();
    updateBulkBar();

    function getSelectionIds() {
        // Retorna todos os IDs do selectionByCountry (fonte de verdade)
        var ids = {};
        Object.keys(selectionByCountry).forEach(function (cc) {
            Object.keys(selectionByCountry[cc]).forEach(function (id) {
                ids[id] = true;
            });
        });
        return Object.keys(ids).map(Number);
    }

    function updateBulkBar() {
        var ids = getSelectionIds();
        var bar = document.getElementById('amsfb-bulk-bar');
        var countEl = document.getElementById('amsfb-bulk-count');
        var panel = document.querySelector('.amsfb-pending-panel');
        if (!bar || !countEl) return;
        if (ids.length > 0) {
            // Contar quantos IDs estão em páginas não visíveis
            var visibleIds = {};
            document.querySelectorAll('.amsfb-row-cb').forEach(function (cb) {
                visibleIds[parseInt(cb.getAttribute('data-id'), 10)] = true;
            });
            var visibleCount = ids.filter(function (id) { return visibleIds[id]; }).length;
            var otherPages = ids.length - visibleCount;

            countEl.textContent = ids.length + ' selecionado(s)';
            if (otherPages > 0) {
                countEl.textContent += ' (' + visibleCount + ' nesta página, ' + otherPages + ' em outras)';
            }
            bar.style.display = 'flex';
            if (panel) panel.classList.add('has-bulk-bar');
        } else {
            bar.style.display = 'none';
            if (panel) panel.classList.remove('has-bulk-bar');
        }
        // Atualizar estado do select-all (checked / indeterminate / unchecked)
        if (selectAllCb) {
            var allCbs = document.querySelectorAll('.amsfb-row-cb:not(:disabled)');
            var checkedCbs = document.querySelectorAll('.amsfb-row-cb:checked:not(:disabled)');
            if (allCbs.length === 0) {
                selectAllCb.checked = false;
                selectAllCb.indeterminate = false;
            } else if (checkedCbs.length === 0) {
                selectAllCb.checked = false;
                selectAllCb.indeterminate = false;
            } else if (checkedCbs.length === allCbs.length) {
                selectAllCb.checked = true;
                selectAllCb.indeterminate = false;
            } else {
                selectAllCb.checked = false;
                selectAllCb.indeterminate = true;
            }
        }
    }

    function removeRowsByIds(ids) {
        ids.forEach(function (id) {
            var row = document.getElementById('amsfb-row-' + id);
            if (row) row.remove();
        });
    }

    function updateCountryCountFromTable() {
        var cards = document.querySelectorAll('.amsfb-country-card');
        cards.forEach(function (card) {
            var cc = card.getAttribute('data-country-code');
            var rows = document.querySelectorAll('#amsfb-pending-tbody tr[data-country-code="' + cc + '"]');
            var countEl = card.querySelector('.amsfb-country-count');
            if (countEl) countEl.textContent = rows.length;
            if (rows.length === 0) card.remove();
        });
        var remaining = document.querySelectorAll('.amsfb-country-card');
        if (remaining.length === 0) {
            var panel = document.querySelector('.amsfb-country-panel');
            if (panel) panel.style.display = 'none';
        }
    }

    function updateGlobalBadge() {
        var badge = document.querySelector('.amsfb-pending-panel .badge');
        var pendingTbody = document.getElementById('amsfb-pending-tbody');
        if (badge && pendingTbody) {
            badge.textContent = pendingTbody.querySelectorAll('tr').length;
        }
    }

    function clearAllSelection() {
        selectionByCountry = {};
        try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
        document.querySelectorAll('.amsfb-row-cb').forEach(function (cb) {
            cb.checked = false;
        });
        if (selectAllCb) {
            selectAllCb.checked = false;
            selectAllCb.indeterminate = false;
        }
        updateBulkBar();
    }

    function addIdToSelection(cc, id) {
        if (!selectionByCountry[cc]) selectionByCountry[cc] = {};
        selectionByCountry[cc][id] = true;
        saveSelection();
    }

    function removeIdFromSelection(id) {
        Object.keys(selectionByCountry).forEach(function (cc) {
            delete selectionByCountry[cc][id];
        });
        saveSelection();
    }

    function removeIdsFromSelection(ids) {
        ids.forEach(function (id) { removeIdFromSelection(id); });
    }

    // -------------------------------------------------------------------------
    // Selecionar por País (cross-page via AJAX)
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-select-country').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var cc = this.getAttribute('data-country-code');
            var name = this.getAttribute('data-country-name');

            // Toggle: se este país já está selecionado, desmarcar
            if (selectionByCountry[cc] && Object.keys(selectionByCountry[cc]).length > 0) {
                // Desmarcar checkboxes visíveis deste país
                var rows = document.querySelectorAll('#amsfb-pending-tbody tr[data-country-code="' + cc + '"]');
                rows.forEach(function (row) {
                    var cb = row.querySelector('.amsfb-row-cb');
                    if (cb) cb.checked = false;
                });
                delete selectionByCountry[cc];
                saveSelection();
                updateBulkBar();
                return;
            }

            // Buscar TODOS os IDs pendentes deste país via AJAX
            btn.disabled = true;
            btn.innerHTML = '&#8987; Buscando...';

            window.AMSFB.post('ai', 'get_ids_by_country', { country_code: cc }, function (data) {
                btn.disabled = false;
                btn.innerHTML = '&#9745; Selecionar';

                if (!data.success || !data.ids || data.ids.length === 0) {
                    alert(data.error || 'Nenhuma sugestão pendente para ' + (name || 'este país') + '.');
                    return;
                }

                // Armazenar IDs no selection manager
                selectionByCountry[cc] = {};
                data.ids.forEach(function (id) { selectionByCountry[cc][id] = true; });
                saveSelection();

                // Marcar checkboxes visíveis na página atual
                var visRows = document.querySelectorAll('#amsfb-pending-tbody tr[data-country-code="' + cc + '"]');
                visRows.forEach(function (row) {
                    var cb = row.querySelector('.amsfb-row-cb');
                    if(cb&&cb.disabled){removeIdFromSelection(parseInt(cb.getAttribute('data-id'),10));return;}
                    if (cb && !cb.disabled) cb.checked = true;
                });

                updateBulkBar();

                // Scroll para a tabela
                var table = document.querySelector('.amsfb-pending-panel .table-responsive');
                if (table) table.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });
    });

    // -------------------------------------------------------------------------
    // Checkbox: select-all header (página atual)
    // -------------------------------------------------------------------------
    if (selectAllCb) {
        selectAllCb.addEventListener('change', function () {
            var checked = this.checked;
            document.querySelectorAll('.amsfb-row-cb').forEach(function (cb) {
                var id = parseInt(cb.getAttribute('data-id'), 10);
                if(cb.disabled){cb.checked=false;removeIdFromSelection(id);return;}
                cb.checked = checked;
                // Ao desmarcar: remover apenas IDs VISÍVEIS do selection manager
                // (não limpar IDs de outras páginas)
                if (!checked && id > 0) {
                    removeIdFromSelection(id);
                }
                // Ao marcar: adicionar IDs visíveis ao selection manager
                if (checked && id > 0) {
                    // Determinar country_code do checkbox
                    var row = cb.closest('tr');
                    var rowCc = row ? (row.getAttribute('data-country-code') || '') : '';
                    addIdToSelection(rowCc, id);
                }
            });
            updateBulkBar();
        });
    }

    // -------------------------------------------------------------------------
    // Checkbox: individual row change
    // -------------------------------------------------------------------------
    document.addEventListener('change', function (e) {
        if (e.target && e.target.classList.contains('amsfb-row-cb')) {
            var id = parseInt(e.target.getAttribute('data-id'), 10);
            if (id > 0) {
                if (e.target.checked) {
                    // Marcar: adicionar ao selection manager
                    var row = e.target.closest('tr');
                    var cc = row ? (row.getAttribute('data-country-code') || '') : '';
                    addIdToSelection(cc, id);
                } else {
                    // Desmarcar: remover do selection manager
                    removeIdFromSelection(id);
                }
            }
            updateBulkBar();
        }
    });

    // -------------------------------------------------------------------------
    // Bulk: Aprovar Selecionados
    // -------------------------------------------------------------------------
    var bulkApproveBtn = document.getElementById('amsfb-bulk-approve-btn');
    if (bulkApproveBtn) {
        bulkApproveBtn.addEventListener('click', function () {
            var ids = getSelectionIds();
            if (ids.length === 0) return;

            // Coletar IPs visíveis para amostra
            var ips = [];
            document.querySelectorAll('.amsfb-row-cb:checked').forEach(function (cb) {
                var row = cb.closest('tr');
                if (row) {
                    var ipEl = row.querySelector('td:nth-child(2) strong');
                    if (ipEl) ips.push(ipEl.textContent.trim());
                }
            });
            var msg = 'Banir ' + ids.length + ' IP(s) selecionado(s)? O fail2ban bloqueará o acesso imediatamente.\n\n';
            if (ips.length > 0) {
                msg += 'IPs visíveis: ' + ips.slice(0, 5).join(', ');
                if (ips.length > 5) msg += '\n...e mais ' + (ips.length - 5);
                msg += '\n';
            }
            if (ids.length > ips.length) {
                msg += '(+' + (ids.length - ips.length) + ' em outras páginas)\n';
            }
            if (!confirm(msg)) return;

            bulkApproveBtn.disabled = true;
            bulkApproveBtn.innerHTML = '&#8987; Banindo...';

            window.AMSFB.post('ai', 'bulk_approve_ids', { ids: JSON.stringify(ids) }, function (data) {
                if (data.success) {
                    removeRowsByIds(data.approved_ids || []);
                    removeRowsByIds(data.dismissed_ids || []);
                    // Desmarcar checkboxes de failed_ids (permanecem na tabela)
                    if (Array.isArray(data.failed_ids)) {
                        data.failed_ids.forEach(function (fid) {
                            var row = document.getElementById('amsfb-row-' + fid);
                            if (row) {
                                var cb = row.querySelector('.amsfb-row-cb');
                                if (cb) cb.checked = false;
                            }
                        });
                    }
                    // Remover IDs processados do selection manager
                    removeIdsFromSelection(data.approved_ids || []);
                    removeIdsFromSelection(data.dismissed_ids || []);
                    removeIdsFromSelection(data.failed_ids || []);
                    updateCountryCountFromTable();
                    updateGlobalBadge();
                    updateBulkBar();
                    alert('✓ ' + (data.message || 'Ação concluída.'));
                } else {
                    alert('✗ ' + (data.error || 'Erro ao banir IPs.'));
                }
                bulkApproveBtn.disabled = false;
                bulkApproveBtn.innerHTML = '&#128683; Banir Selecionados';
            });
        });
    }

    // -------------------------------------------------------------------------
    // Bulk: Rejeitar Selecionados
    // -------------------------------------------------------------------------
    var bulkRejectBtn = document.getElementById('amsfb-bulk-reject-btn');
    if (bulkRejectBtn) {
        bulkRejectBtn.addEventListener('click', function () {
            var ids = getSelectionIds();
            if (ids.length === 0) return;
            if (!confirm('Rejeitar ' + ids.length + ' sugestão(ões)?')) return;

            bulkRejectBtn.disabled = true;
            bulkRejectBtn.innerHTML = '&#8987; Rejeitando...';

            window.AMSFB.post('ai', 'bulk_reject_ids', { ids: JSON.stringify(ids) }, function (data) {
                if (data.success) {
                    removeRowsByIds(data.rejected_ids || []);
                    removeIdsFromSelection(data.rejected_ids || []);
                    updateCountryCountFromTable();
                    updateGlobalBadge();
                    updateBulkBar();
                    alert('✓ ' + (data.message || 'Ação concluída.'));
                } else {
                    alert('✗ ' + (data.error || 'Erro ao rejeitar.'));
                }
                bulkRejectBtn.disabled = false;
                bulkRejectBtn.innerHTML = '&#10007; Rejeitar Selecionados';
            });
        });
    }

    // -------------------------------------------------------------------------
    // Bulk: Limpar seleção
    // -------------------------------------------------------------------------
    var bulkClearBtn = document.getElementById('amsfb-bulk-clear-btn');
    if (bulkClearBtn) {
        bulkClearBtn.addEventListener('click', function () {
            clearAllSelection();
        });
    }

})();
</script>
