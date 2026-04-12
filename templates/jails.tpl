<?php
/**
 * Jails list template
 * Available: $jail_data (array), $live_status (array), $error
 */
?>

<div class="amsfb-page-header">
    <h3>&#128274; Jails</h3>
    <button class="btn btn-sm btn-success" data-toggle="modal" data-target="#modalAddJail">
        + Novo Jail
    </button>
</div>

<?php if ($error): ?>
<div class="alert alert-warning"><?= $e($error) ?></div>
<?php endif; ?>

<?php if (empty($jail_data)): ?>
<div class="alert alert-info">Nenhum jail encontrado em jail.local. Verifique o caminho nas configurações do módulo.</div>
<?php else: ?>

<div class="table-responsive">
    <table class="table table-striped table-hover amsfb-table">
        <thead>
            <tr>
                <th>Jail</th>
                <th>Status</th>
                <th>Banidos</th>
                <th>maxretry</th>
                <th>findtime</th>
                <th>bantime</th>
                <th style="width:150px;">Ações</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($jail_data as $jail => $cfg): ?>
            <?php
            $enabled  = isset($cfg['enabled']) ? strtolower($cfg['enabled']) !== 'false' : true;
            $live     = $live_status[$jail] ?? null;
            $banned   = $live ? (int)$live['currently_banned'] : '-';
            ?>
            <tr id="row-<?= $e($jail) ?>">
                <td><strong><?= $e($jail) ?></strong></td>
                <td>
                    <span class="label amsfb-jail-status-label <?= $enabled ? 'label-success' : 'label-default' ?>"
                          id="status-<?= $e($jail) ?>">
                        <?= $enabled ? 'Habilitado' : 'Desabilitado' ?>
                    </span>
                </td>
                <td>
                    <?php if (is_int($banned)): ?>
                    <span class="badge <?= $banned > 0 ? 'badge-danger' : 'badge-default' ?>">
                        <?= $banned ?>
                    </span>
                    <?php else: ?>
                    <span class="text-muted">-</span>
                    <?php endif; ?>
                </td>
                <td><?= $e($cfg['maxretry'] ?? '-') ?></td>
                <td><?= $e($cfg['findtime'] ?? '-') ?>s</td>
                <td><?= $e($cfg['bantime']  ?? '-') ?>s</td>
                <td>
                    <a href="<?= $e($modulelink . '&action=jail_edit&jail=' . urlencode($jail)) ?>"
                       class="btn btn-xs btn-primary">Editar</a>

                    <!-- Toggle button (AJAX-enhanced, degrades to form POST) -->
                    <button type="button"
                            class="btn btn-xs <?= $enabled ? 'btn-warning' : 'btn-success' ?> amsfb-toggle-btn"
                            data-jail="<?= $e($jail) ?>"
                            data-enabled="<?= $enabled ? '1' : '0' ?>">
                        <?= $enabled ? 'Desabilitar' : 'Habilitar' ?>
                    </button>

                    <!-- Remove button (AJAX) -->
                    <button type="button"
                            class="btn btn-xs btn-danger amsfb-remove-btn"
                            data-jail="<?= $e($jail) ?>">
                        Remover
                    </button>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Non-AJAX fallback forms (hidden, submitted via JS) -->
<?php foreach ($jail_data as $jail => $cfg): ?>
    <?php $enabled = isset($cfg['enabled']) ? strtolower($cfg['enabled']) !== 'false' : true; ?>
    <form id="form-toggle-<?= $e($jail) ?>" method="post"
          action="<?= $e($modulelink . '&action=jails') ?>" style="display:none;">
        <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
        <input type="hidden" name="jail" value="<?= $e($jail) ?>">
        <input type="hidden" name="do"   value="<?= $enabled ? 'disable' : 'enable' ?>" id="do-<?= $e($jail) ?>">
    </form>
<?php endforeach; ?>

<?php endif; ?>

<!-- Modal: Novo Jail -->
<div class="modal fade" id="modalAddJail" tabindex="-1" role="dialog" aria-labelledby="modalAddJailLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="<?= $e($modulelink . '&action=jails') ?>">
                <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
                <input type="hidden" name="do" value="add">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Fechar">
                        <span aria-hidden="true">&times;</span>
                    </button>
                    <h4 class="modal-title" id="modalAddJailLabel">Novo Jail</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>Nome do Jail <span class="text-danger">*</span></label>
                        <input type="text" name="new_jail" class="form-control" required
                               pattern="^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$"
                               placeholder="ex: apache-auth">
                        <span class="help-block">Apenas letras, números, hífen e underscore.</span>
                    </div>
                    <div class="form-group">
                        <label>Filter</label>
                        <select name="filter" class="form-control">
                            <option value="">— nenhum —</option>
                            <?php foreach ($available_filters as $f): ?>
                            <option value="<?= $e($f) ?>"><?= $e($f) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <span class="help-block">Filtros disponíveis em /etc/fail2ban/filter.d/.</span>
                    </div>
                    <div class="form-group">
                        <label>Log Path</label>
                        <input type="text" name="logpath" class="form-control"
                               placeholder="/var/log/...">
                    </div>
                    <div class="row">
                        <div class="col-sm-4">
                            <div class="form-group">
                                <label>maxretry</label>
                                <input type="number" name="maxretry" class="form-control" value="5" min="1" max="100">
                            </div>
                        </div>
                        <div class="col-sm-4">
                            <div class="form-group">
                                <label>findtime (s)</label>
                                <input type="number" name="findtime" class="form-control" value="600" min="60" max="86400">
                            </div>
                        </div>
                        <div class="col-sm-4">
                            <div class="form-group">
                                <label>bantime (s)</label>
                                <input type="number" name="bantime" class="form-control" value="3600" min="60">
                            </div>
                        </div>
                    </div>
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" name="enabled" value="1" checked> Habilitar jail
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-success">Criar Jail</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
(function () {
    document.querySelectorAll('.amsfb-toggle-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var jail    = this.dataset.jail;
            var enabled = this.dataset.enabled === '1';
            var newDo   = enabled ? 'disable' : 'enable';
            var self    = this;

            self.disabled = true;
            self.textContent = '...';

            fetch(window.AMSFB.moduleLink + '&action=jails&do=' + newDo, {
                method:  'POST',
                headers: {
                    'Content-Type':      'application/x-www-form-urlencoded',
                    'X-Requested-With':  'XMLHttpRequest',
                },
                body: 'csrf_token=' + encodeURIComponent(window.AMSFB.csrfToken)
                    + '&jail='       + encodeURIComponent(jail)
                    + '&do='         + encodeURIComponent(newDo),
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                // [SEC-7] Sync rotated CSRF token
                if (data.csrf_token) { window.AMSFB.csrfToken = data.csrf_token; }
                if (data.success) {
                    var nowEnabled   = (newDo === 'enable');
                    self.dataset.enabled  = nowEnabled ? '1' : '0';
                    self.textContent      = nowEnabled ? 'Desabilitar' : 'Habilitar';
                    self.className        = 'btn btn-xs amsfb-toggle-btn ' + (nowEnabled ? 'btn-warning' : 'btn-success');

                    var lbl = document.getElementById('status-' + jail);
                    if (lbl) {
                        lbl.textContent  = nowEnabled ? 'Habilitado' : 'Desabilitado';
                        lbl.className    = 'label amsfb-jail-status-label ' + (nowEnabled ? 'label-success' : 'label-default');
                    }
                } else {
                    alert('Erro: ' + (data.error || 'Falha desconhecida'));
                    self.disabled    = false;
                    self.textContent = enabled ? 'Desabilitar' : 'Habilitar';
                }
            })
            .catch(function () {
                // AJAX failed — fall back to form POST
                var form = document.getElementById('form-toggle-' + jail);
                if (form) { form.submit(); }
            });
        });
    });
    // Atualiza o CSRF do modal ao abrir — evita token stale após rotação por AJAX
    (function () {
        var modalEl = document.getElementById('modalAddJail');
        if (!modalEl) return;
        function syncCsrf() {
            var inp = modalEl.querySelector('input[name="csrf_token"]');
            if (inp) { inp.value = window.AMSFB.csrfToken; }
        }
        // Bootstrap 3 (jQuery) — usado pelo WHMCS
        if (typeof $ !== 'undefined') {
            $(modalEl).on('show.bs.modal', syncCsrf);
        }
        // Bootstrap 5 fallback
        modalEl.addEventListener('show.bs.modal', syncCsrf);
    })();

    // Remove buttons (AJAX)
    document.querySelectorAll('.amsfb-remove-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var jail = this.dataset.jail;
            if (!confirm('Remover o jail "' + jail + '" do jail.local?\nEsta ação não pode ser desfeita.')) {
                return;
            }

            btn.disabled    = true;
            btn.textContent = '...';

            fetch(window.AMSFB.moduleLink + '&action=jails&do=remove', {
                method:  'POST',
                headers: {
                    'Content-Type':     'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                body: 'csrf_token=' + encodeURIComponent(window.AMSFB.csrfToken)
                    + '&jail='       + encodeURIComponent(jail)
                    + '&do=remove',
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.csrf_token) { window.AMSFB.csrfToken = data.csrf_token; }
                if (data.success) {
                    var row = document.getElementById('row-' + jail);
                    if (row) { row.parentNode.removeChild(row); }
                } else {
                    alert('Erro ao remover jail: ' + (data.error || 'Falha desconhecida'));
                    btn.disabled    = false;
                    btn.textContent = 'Remover';
                }
            })
            .catch(function () {
                btn.disabled    = false;
                btn.textContent = 'Remover';
                alert('Falha de comunicação. Tente novamente.');
            });
        });
    });
})();
</script>
