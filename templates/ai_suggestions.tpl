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
    <a href="<?= $e($modulelink . '&action=ai_settings') ?>" class="btn btn-sm btn-default">&#9881; Configurações</a>
</div>

<!-- =========================================================
     Seção 0: Ações por País (bulk)
     ========================================================= -->
<?php if (!empty($country_groups)): ?>
<div class="panel panel-default amsfb-country-panel">
    <div class="panel-heading">
        <strong>&#127758; Ações por País</strong>
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
                    <button class="btn btn-xs btn-success amsfb-bulk-approve-country"
                            data-country-code="<?= $e($cc) ?>"
                            data-country-name="<?= $label ?>"
                            data-count="<?= (int)$cg['ip_count'] ?>"
                            title="Banir todos os IPs deste país">
                        &#128683; Banir Todos
                    </button>
                    <button class="btn btn-xs btn-danger amsfb-bulk-reject-country"
                            data-country-code="<?= $e($cc) ?>"
                            data-country-name="<?= $label ?>"
                            data-count="<?= (int)$cg['ip_count'] ?>"
                            title="Rejeitar todas as sugestões deste país">
                        &#10007; Rejeitar
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
<div class="panel panel-default">
    <div class="panel-heading">
        <strong>&#9203; Aguardando Aprovação</strong>
        <?php if ($pending_total > 0): ?>
        <span class="badge" style="background:#e74c3c; margin-left:8px;"><?= (int)$pending_total ?></span>
        <?php endif; ?>
    </div>

    <?php if (empty($pending)): ?>
    <div class="panel-body text-muted">Nenhuma sugestão pendente.</div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-striped table-hover amsfb-table amsfb-table-sm">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Ameaça</th>
                    <th>Severidade</th>
                    <th>Confiança</th>
                    <th>Jail</th>
                    <th>Filtro</th>
                    <th>Bantime</th>
                    <th>Data</th>
                    <th>Ações</th>
                </tr>
            </thead>
            <tbody id="amsfb-pending-tbody">
            <?php foreach ($pending as $s): ?>
                <tr id="amsfb-row-<?= (int)$s['id'] ?>"
                    data-country-code="<?= $e($geo_data[$s['ip']]['country_code'] ?? '') ?>">
                    <td>
                        <strong><?= $e($s['ip']) ?></strong>
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
                    <td>
                        <div class="amsfb-confidence-bar">
                            <div class="amsfb-confidence-fill" style="width:<?= (int)$s['confidence'] ?>%"></div>
                            <span><?= (int)$s['confidence'] ?>%</span>
                        </div>
                    </td>
                    <td><?= $e($s['jail'] ?: '-') ?></td>
                    <td>
                        <?php if (!empty($s['filter_name'])): ?>
                            <code style="font-size:11px;"
                                  title="failregex: <?= $e($s['failregex'] ?? '') ?>">amsfb-<?= $e($s['filter_name']) ?></code>
                            <?php if (!empty($s['filter_created_at'])): ?>
                                <br><small class="text-success">&#10003; criado</small>
                            <?php endif; ?>
                        <?php else: ?>
                            <span class="text-muted">-</span>
                        <?php endif; ?>
                    </td>
                    <td><?= $s['bantime'] ? $e($s['bantime'] . 's') : '-' ?></td>
                    <td><?= $e($s['created_at'] ?? '-') ?></td>
                    <td class="amsfb-action-btns">
                        <button class="btn btn-xs btn-success amsfb-approve-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                title="Banir este IP imediatamente">
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
                        <button class="btn btn-xs <?= !empty($s['filter_created_at']) ? 'btn-success' : 'btn-default' ?> amsfb-create-filter-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                data-filter-name="<?= $e($s['filter_name'] ?? '') ?>"
                                data-has-regex="<?= !empty($s['failregex']) ? '1' : '0' ?>"
                                data-failregex="<?= $e($s['failregex'] ?? '') ?>"
                                <?= !empty($s['filter_created_at']) ? 'disabled' : '' ?>
                                title="<?= !empty($s['failregex']) ? 'Criar filtro fail2ban para este padrão de ataque' : 'A IA irá gerar um failregex a partir das evidências e criar o filtro' ?>">
                            <?= !empty($s['filter_created_at']) ? '&#10003; Filtro criado' : '&#128736; Criar Filtro' ?>
                        </button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Paginação da fila pendente -->
    <?php if ($pending_pages > 1): ?>
    <div class="amsfb-pagination-wrap">
        <nav aria-label="Paginação pendentes">
            <ul class="pagination pagination-sm">
                <?php if ($pending_page > 1): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&pending_page=' . ($pending_page - 1)) ?>">&laquo;</a>
                </li>
                <?php endif; ?>

                <?php
                $pStart = max(1, $pending_page - 3);
                $pEnd   = min($pending_pages, $pending_page + 3);
                for ($p = $pStart; $p <= $pEnd; $p++):
                ?>
                <li class="<?= $p === $pending_page ? 'active' : '' ?>">
                    <a href="<?= $e($modulelink . '&action=ai&pending_page=' . $p) ?>"><?= $p ?></a>
                </li>
                <?php endfor; ?>

                <?php if ($pending_page < $pending_pages): ?>
                <li>
                    <a href="<?= $e($modulelink . '&action=ai&pending_page=' . ($pending_page + 1)) ?>">&raquo;</a>
                </li>
                <?php endif; ?>
            </ul>
        </nav>
        <p class="text-muted amsfb-pagination-info">
            <?= (int)$pending_total ?> sugestão(ões) pendente(s) &mdash; página <?= (int)$pending_page ?> de <?= (int)$pending_pages ?>
        </p>
    </div>
    <?php endif; ?>

    <?php endif; ?>
</div>

<!-- =========================================================
     Seção 2: Histórico com filtros
     ========================================================= -->
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

    function getIPsByCountry(countryCode) {
        var ips = [];
        var rows = document.querySelectorAll('#amsfb-pending-tbody tr[data-country-code="' + countryCode + '"]');
        rows.forEach(function (row) {
            var ipCell = row.querySelector('td:first-child strong');
            if (ipCell) ips.push(ipCell.textContent.trim());
        });
        return ips;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
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

            if (!confirm(msg)) return;

            self.disabled = true;
            self.innerHTML = hasRegex ? '&#8987; Criando...' : '&#8987; Gerando...';

            window.AMSFB.post('ai', 'create_filter', { id: id }, function (data) {
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
    if (runNowBtn) {
        runNowBtn.addEventListener('click', function () {
            if (!confirm('Rodar análise de IA agora em todos os logs configurados?')) return;
            runNowBtn.disabled = true;

            // 1. Buscar lista de logs
            runNowBtn.innerHTML = '&#9203; Buscando logs...';
            window.AMSFB.post('ai', 'list_logs', {}, function (data) {
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
                var pendingTbody = document.getElementById('amsfb-pending-tbody');
                var badge = document.querySelector('.panel-heading .badge');

                // 2. Analisar cada log sequencialmente
                function analyzeNext() {
                    if (current >= logs.length) {
                        // Finalizado
                        runNowBtn.disabled = false;
                        runNowBtn.innerHTML = '&#9654; Analisar agora';
                        var analyzed = total - totalSkipped;
                        var msg = '✓ Análise concluída — ' + analyzed + ' log(s) analisado(s)';
                        if (totalSkipped > 0) {
                            msg += ', ' + totalSkipped + ' pulado(s) (sem dados novos)';
                        }
                        if (totalSaved > 0) {
                            msg += '. ' + totalSaved + ' sugestão(ões) encontrada(s).';
                        } else {
                            msg += '. Nenhuma ameaça encontrada.';
                        }
                        alert(msg);
                        return;
                    }

                    var log = logs[current];
                    current++;
                    runNowBtn.innerHTML = '&#9203; Analisando: ' + (log.label || log.path) + ' (' + current + '/' + total + ')...';

                    window.AMSFB.post('ai', 'analyze_log', { path: log.path }, function (result) {
                        // Diferenciar "sem conteúdo novo" (pulado) de "analisado sem ameaças"
                        if (result.success && result.message) {
                            // Log pulado — sem conteúdo novo (watermark)
                            totalSkipped++;
                        }

                        if (result.success && result.suggestions && result.suggestions.length > 0) {
                            totalSaved += result.saved;

                            // Adicionar linhas na tabela
                            result.suggestions.forEach(function (s) {
                                if (!pendingTbody) return;
                                // Verificar se já existe (dedup visual)
                                if (document.getElementById('amsfb-row-' + s.id)) return;

                                var tr = document.createElement('tr');
                                tr.id = 'amsfb-row-' + s.id;
                                tr.setAttribute('data-country-code', '');

                                // Botões de ação (mesmos da carga inicial PHP)
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
                                    '<td><strong>' + escapeHtml(s.ip || '') + '</strong></td>'
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

                                // Inserir no início da tabela
                                if (pendingTbody.firstChild) {
                                    pendingTbody.insertBefore(tr, pendingTbody.firstChild);
                                } else {
                                    pendingTbody.appendChild(tr);
                                }

                                // Bindar eventos (mesmos da carga inicial PHP)
                                bindAllHandlers(tr);
                            });

                            // Atualizar badge
                            if (badge) {
                                var count = pendingTbody.querySelectorAll('tr').length;
                                badge.textContent = count;
                            }
                        }

                        // Próximo log
                        analyzeNext();
                    });
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

                            if (!confirm(msg)) return;
                            self.disabled = true;
                            self.innerHTML = hasRegex ? '&#8987; Criando...' : '&#8987; Gerando...';

                            window.AMSFB.post('ai', 'create_filter', { id: id }, function (data) {
                                if (data.success) {
                                    self.innerHTML = '&#10003; Filtro criado';
                                    self.disabled = true;
                                    self.classList.remove('btn-default');
                                    self.classList.add('btn-success');
                                    alert('✓ ' + (data.message || 'Filtro criado.'));
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
        });
    }

    // -------------------------------------------------------------------------
    // Bulk: Banir Todos por País
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-bulk-approve-country').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var cc    = this.getAttribute('data-country-code');
            var name  = this.getAttribute('data-country-name');
            var count = parseInt(this.getAttribute('data-count'), 10) || 0;
            var ips   = getIPsByCountry(cc);

            var msg = 'Banir todos os ' + count + ' IP(s) de ' + name + '?\n\n';
            if (ips.length > 0) {
                msg += 'IPs: ' + ips.slice(0, 5).join(', ');
                if (ips.length > 5) msg += '\n...e mais ' + (ips.length - 5);
                msg += '\n';
            }
            msg += '\nOs IPs serão banidos pelo fail2ban imediatamente.';
            if (!confirm(msg)) return;

            btn.disabled = true;
            btn.innerHTML = '&#8987; Banindo...';
            var card = btn.closest('.amsfb-country-card');

            window.AMSFB.post('ai', 'bulk_approve_country', { country_code: cc }, function (data) {
                if (data.success) {
                    // Remover linhas da tabela (aprovadas + falhadas permanecem)
                    if (Array.isArray(data.approved_ids)) {
                        data.approved_ids.forEach(function (aid) {
                            var row = document.getElementById('amsfb-row-' + aid);
                            if (row) row.remove();
                        });
                    }
                    // Remover duplicatas dispensadas
                    if (Array.isArray(data.dismissed_ids)) {
                        data.dismissed_ids.forEach(function (did) {
                            var dup = document.getElementById('amsfb-row-' + did);
                            if (dup) dup.remove();
                        });
                    }
                    // Atualizar ou remover card
                    if (card) {
                        if (Array.isArray(data.failed_ids) && data.failed_ids.length > 0) {
                            // Alguns falharam — atualizar contagem
                            var countEl = card.querySelector('.amsfb-country-count');
                            if (countEl) countEl.textContent = data.failed_ids.length;
                            btn.disabled = false;
                            btn.innerHTML = '&#128683; Banir Todos';
                        } else {
                            card.remove();
                            // Esconder painel se não restam cards
                            var remaining = document.querySelectorAll('.amsfb-country-card');
                            if (remaining.length === 0) {
                                var panel = document.querySelector('.amsfb-country-panel');
                                if (panel) panel.style.display = 'none';
                            }
                        }
                    }
                    // Atualizar badge geral
                    var badge = document.querySelector('.panel-heading .badge');
                    var pendingTbody = document.getElementById('amsfb-pending-tbody');
                    if (badge && pendingTbody) {
                        badge.textContent = pendingTbody.querySelectorAll('tr').length;
                    }
                    alert('✓ ' + (data.message || 'Ação concluída.'));
                } else {
                    btn.disabled = false;
                    btn.innerHTML = '&#128683; Banir Todos';
                    alert('✗ ' + (data.error || 'Erro ao banir IPs.'));
                }
            });
        });
    });

    // -------------------------------------------------------------------------
    // Bulk: Rejeitar Todos por País
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-bulk-reject-country').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var cc    = this.getAttribute('data-country-code');
            var name  = this.getAttribute('data-country-name');
            var count = parseInt(this.getAttribute('data-count'), 10) || 0;
            var ips   = getIPsByCountry(cc);

            var msg = 'Rejeitar todas as ' + count + ' sugestão(ões) de ' + name + '?\n\n';
            if (ips.length > 0) {
                msg += 'IPs: ' + ips.slice(0, 5).join(', ');
                if (ips.length > 5) msg += '\n...e mais ' + (ips.length - 5);
                msg += '\n';
            }
            if (!confirm(msg)) return;

            btn.disabled = true;
            btn.innerHTML = '&#8987; Rejeitando...';
            var card = btn.closest('.amsfb-country-card');

            window.AMSFB.post('ai', 'bulk_reject_country', { country_code: cc }, function (data) {
                if (data.success) {
                    // Remover todas as linhas do país
                    var rows = document.querySelectorAll('#amsfb-pending-tbody tr[data-country-code="' + cc + '"]');
                    rows.forEach(function (row) { row.remove(); });
                    // Remover card
                    if (card) {
                        card.remove();
                        // Esconder painel se não restam cards
                        var remaining = document.querySelectorAll('.amsfb-country-card');
                        if (remaining.length === 0) {
                            var panel = document.querySelector('.amsfb-country-panel');
                            if (panel) panel.style.display = 'none';
                        }
                    }
                    // Atualizar badge geral
                    var badge = document.querySelector('.panel-heading .badge');
                    var pendingTbody = document.getElementById('amsfb-pending-tbody');
                    if (badge && pendingTbody) {
                        badge.textContent = pendingTbody.querySelectorAll('tr').length;
                    }
                    alert('✓ ' + (data.message || 'Ação concluída.'));
                } else {
                    btn.disabled = false;
                    btn.innerHTML = '&#10007; Rejeitar';
                    alert('✗ ' + (data.error || 'Erro ao rejeitar.'));
                }
            });
        });
    });

})();
</script>
