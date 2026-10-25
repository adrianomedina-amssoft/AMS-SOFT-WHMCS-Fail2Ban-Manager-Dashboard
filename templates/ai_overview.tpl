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

<div id="amsfb-ai-view" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>" data-view="<?= $e($decision_view) ?>">
<div class="amsfb-page-header">
    <h3>&#129302; Sugestões da IA</h3>
    <button id="amsfb-run-now-btn" class="btn btn-sm btn-primary">
        &#9654; Análise manual das fontes
    </button>
    <button id="amsfb-stop-btn" class="btn btn-sm btn-danger" style="display:none;">
        &#9726; Parar
    </button>
    <a href="<?= $e($modulelink . '&action=ai_settings') ?>" class="btn btn-sm btn-default">&#9881; Configurações</a>
</div>
<div class="alert alert-info" id="amsfb-ai-result" role="status" aria-live="polite">Dados desta consulta. Após ações, atualize para obter as categorias atuais. Localização usa somente cache local; ausência de país não é evidência de ataque.</div>
<button type="button" id="amsfb-ai-refresh" class="btn btn-default btn-sm">Atualizar dados</button>
<p class="text-muted">Análise manual usa uma amostra final por fonte, pode consumir tokens e não avança a coleta automática. Não é uma varredura integral de todos os logs. Cada fonte será tentada uma vez; Parar interrompe as próximas fontes, não cancela uma chamada já enviada.</p>
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
                                data-evidence="<?= $e(json_encode($s['evidence'] ?? [],JSON_INVALID_UTF8_SUBSTITUTE)) ?>"
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
    <tr><td><?= $e($s['ip']) ?></td><td><?= $e($s['classification']) ?><?php if(!empty($s['vector_review'])): ?><br><span class="label label-warning">Vetor para triagem</span><?php endif ?></td><td><?= $e($s['threat']) ?></td><td><?= (int)$s['confidence'] ?>%</td><td><?= $e($s['event_at']??'Evento não comprovado') ?><br><small><?= $e($s['recency']??'') ?> — análise: <?= $e($s['created_at']) ?></small></td><td><details><summary>Consultar</summary><pre><?= $e(json_encode($s['evidence']??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE)) ?></pre></details></td></tr>
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
    <?php foreach($learning['data'] as $item): ?><tr><td>#<?= (int)$item['id'] ?><br><?= $e($item['ip']) ?></td><td><?= $e($learningLabels[$item['learning_group']]??$item['learning_group']) ?></td><td><?= $e($learningReasons[$item['code']]??$item['code']) ?><?php if($item['retry_at']): ?><br><small>Próxima tentativa a partir de <?= $e(date('d/m/Y H:i:s',(int)$item['retry_at'])) ?></small><?php endif ?></td><td><?= $e($item['updated_at']) ?></td><td><details><summary>Consultar</summary><pre><?= $e(json_encode($item['evidence'],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE)) ?></pre></details></td></tr><?php endforeach ?>
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
                                data-evidence="<?= $e(json_encode($s['evidence'] ?? [],JSON_INVALID_UTF8_SUBSTITUTE)) ?>"
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


</div>
<script src="<?= $e($asset_base) ?>/js/ai.js?v=2.2.48"></script>
