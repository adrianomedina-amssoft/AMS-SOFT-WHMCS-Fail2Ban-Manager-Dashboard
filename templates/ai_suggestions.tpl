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
    <a href="<?= $e($modulelink . '&action=ai_settings') ?>" class="btn btn-sm btn-default">&#9881; Configurações</a>
</div>

<!-- =========================================================
     Seção 1: Fila Pendente
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading">
        <strong>&#9203; Aguardando Aprovação</strong>
        <?php if (!empty($pending)): ?>
        <span class="badge" style="background:#e74c3c; margin-left:8px;"><?= count($pending) ?></span>
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
                    <th>Bantime</th>
                    <th>Data</th>
                    <th>Ações</th>
                </tr>
            </thead>
            <tbody id="amsfb-pending-tbody">
            <?php foreach ($pending as $s): ?>
                <tr id="amsfb-row-<?= (int)$s['id'] ?>">
                    <td><strong><?= $e($s['ip']) ?></strong></td>
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
                    <td><?= $s['bantime'] ? $e($s['bantime'] . 's') : '-' ?></td>
                    <td><?= $e($s['created_at'] ?? '-') ?></td>
                    <td class="amsfb-action-btns">
                        <button class="btn btn-xs btn-success amsfb-approve-btn"
                                data-id="<?= (int)$s['id'] ?>"
                                title="Aprovar e executar ban">
                            &#10003; Aprovar
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
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
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
                    <td><?= $e($s['ip']) ?></td>
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
                    if (row) row.remove();
                    alert('✓ ' + (data.message || 'Aprovado.'));
                } else if (data.jail_missing) {
                    // Jail inexistente: mostrar aviso inline com link para criar
                    self.disabled = false;
                    var createUrl = window.AMSFB.moduleLink
                        + '&action=jails'
                        + '&new_jail='    + encodeURIComponent(data.jail_name || '')
                        + '&bantime='     + encodeURIComponent(data.bantime   || 3600)
                        + '&open_modal=1';
                    var cell = self.closest('td');
                    // Remover aviso anterior se houver
                    var old = cell.querySelector('.amsfb-jail-missing-msg');
                    if (old) old.remove();
                    var msg = document.createElement('div');
                    msg.className = 'amsfb-jail-missing-msg';
                    msg.style.cssText = 'margin-top:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;';
                    msg.innerHTML = '<span style="color:#c0392b;font-size:12px;">&#9888; Jail <strong>'
                        + data.jail_name.replace(/[<>"&]/g, function(c){return {'<':'&lt;','>':'&gt;','"':'&quot;','&':'&amp;'}[c];})
                        + '</strong> não existe.</span>'
                        + '<a href="' + createUrl + '" class="btn btn-xs btn-primary">+ Criar Jail</a>';
                    cell.appendChild(msg);
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
                    if (row) row.remove();
                } else {
                    self.disabled = false;
                    alert('✗ ' + (data.error || 'Erro ao rejeitar.'));
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

})();
</script>
