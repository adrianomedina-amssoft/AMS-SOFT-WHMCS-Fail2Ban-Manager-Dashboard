<?php
/**
 * Log Paths template
 * Available: $jail_paths (array: jail => ['path' => ..., 'validation' => [...]])
 */
?>

<div class="amsfb-page-header">
    <h3>&#128196; Log Paths</h3>
</div>

<p class="text-muted">
    Mapeie cada jail ao seu arquivo de log. Os caminhos são salvos no banco de dados e aplicados ao jail.local.
</p>

<?php if (empty($jail_paths)): ?>
<div class="alert alert-info">Nenhum jail encontrado. Verifique o caminho do jail.local nas configurações do módulo.</div>
<?php else: ?>

<form method="post" action="<?= $e($modulelink . '&action=logpaths') ?>">
    <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
    <input type="hidden" name="do" value="save">

    <div class="panel panel-default">
        <div class="table-responsive">
            <table class="table table-striped amsfb-table">
                <thead>
                    <tr>
                        <th style="width:180px;">Jail</th>
                        <th>Log Path</th>
                        <th style="width:100px;">Validar</th>
                        <th style="width:220px;">Status</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($jail_paths as $jail => $info): ?>
                    <?php $v = $info['validation']; ?>
                    <tr>
                        <td><strong><?= $e($jail) ?></strong></td>
                        <td>
                            <input type="text"
                                   class="form-control amsfb-logpath-input"
                                   name="logpath[<?= $e($jail) ?>]"
                                   id="logpath-<?= $e($jail) ?>"
                                   value="<?= $e($info['path']) ?>"
                                   placeholder="/var/log/...">
                        </td>
                        <td>
                            <button type="button"
                                    class="btn btn-sm btn-default amsfb-validate-btn"
                                    data-jail="<?= $e($jail) ?>">
                                Validar
                            </button>
                        </td>
                        <td>
                            <span class="amsfb-val-result" id="valresult-<?= $e($jail) ?>">
                                <?php if ($v !== null): ?>
                                    <?php if ($v['exists'] && $v['readable']): ?>
                                    <span class="text-success">
                                        &#10003; Legível
                                        (<?= $e(\AMS\Fail2Ban\Helper::fmtBytes((int)$v['size'])) ?>)
                                    </span>
                                    <?php elseif ($v['exists']): ?>
                                    <span class="text-warning">&#9888; Não legível</span>
                                    <?php else: ?>
                                    <span class="text-danger">&#10007; Não encontrado</span>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </span>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="panel-footer">
            <button type="submit" class="btn btn-primary">Salvar Caminhos</button>
        </div>
    </div>
</form>
<?php endif; ?>

<script>
(function () {
    document.querySelectorAll('.amsfb-validate-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var jail    = this.dataset.jail;
            var input   = document.getElementById('logpath-' + jail);
            var resSpan = document.getElementById('valresult-' + jail);
            if (!input || !resSpan) return;

            var path = input.value.trim();
            if (!path) return;

            btn.disabled    = true;
            btn.textContent = '...';
            resSpan.innerHTML = '<span class="text-muted">Verificando...</span>';

            fetch(window.AMSFB.moduleLink + '&action=logpaths&do=validate', {
                method: 'POST',
                headers: {
                    'Content-Type':     'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                body: 'csrf_token=' + encodeURIComponent(window.AMSFB.csrfToken)
                    + '&path='      + encodeURIComponent(path),
            })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                // [SEC-7] Sync rotated CSRF token
                if (d.csrf_token) { window.AMSFB.csrfToken = d.csrf_token; }
                btn.disabled    = false;
                btn.textContent = 'Validar';

                if (!d.success) {
                    resSpan.innerHTML = '<span class="text-danger">&#10007; ' + escHtml(d.error || 'Erro') + '</span>';
                    return;
                }
                if (d.exists && d.readable) {
                    resSpan.innerHTML = '<span class="text-success">&#10003; Legível (' + formatBytes(d.size) + ')</span>';
                } else if (d.exists) {
                    resSpan.innerHTML = '<span class="text-warning">&#9888; Não legível</span>';
                } else {
                    resSpan.innerHTML = '<span class="text-danger">&#10007; Não encontrado</span>';
                }
            })
            .catch(function () {
                btn.disabled    = false;
                btn.textContent = 'Validar';
                resSpan.innerHTML = '<span class="text-warning">&#9888; AJAX falhou</span>';
            });
        });
    });

    function escHtml(s) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }
    function formatBytes(b) {
        if (b < 1024)    return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(2) + ' MB';
    }
})();
</script>
