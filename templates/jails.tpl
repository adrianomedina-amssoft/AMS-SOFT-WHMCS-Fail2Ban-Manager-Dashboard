<?php
/**
 * Jails list template
 * Available: $jail_data (array), $live_status (array), $error
 */
?>

<div class="amsfb-page-header">
    <h3>&#128274; Jails</h3>
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
})();
</script>
