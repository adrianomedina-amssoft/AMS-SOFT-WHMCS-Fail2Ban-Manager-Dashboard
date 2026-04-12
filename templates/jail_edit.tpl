<?php
/**
 * Jail edit form
 * Available: $jail (string), $jail_data (array with keys: enabled, maxretry, findtime, bantime, logpath, ...)
 */
$jd = $jail_data;
$defaultEnabled  = isset($jd['enabled']) ? strtolower($jd['enabled']) !== 'false' : true;
$defaultMaxretry = (int)($jd['maxretry'] ?? 5);
$defaultFindtime = (int)($jd['findtime'] ?? 600);
$defaultBantime  = (int)($jd['bantime']  ?? 3600);
$defaultLogpath  = $jd['logpath'] ?? '';
?>

<div class="amsfb-page-header">
    <h3>&#128274; Editar Jail: <code><?= $e($jail) ?></code></h3>
    <a href="<?= $e($modulelink . '&action=jails') ?>" class="btn btn-sm btn-default">&larr; Voltar</a>
</div>

<div class="panel panel-default" style="max-width:640px;">
    <div class="panel-body">
        <form method="post" action="<?= $e($modulelink . '&action=jail_edit&jail=' . urlencode($jail)) ?>">
            <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
            <input type="hidden" name="do"         value="save">
            <input type="hidden" name="jail"       value="<?= $e($jail) ?>">

            <!-- Enabled -->
            <div class="form-group">
                <div class="checkbox">
                    <label>
                        <input type="checkbox" name="enabled" value="1"
                               <?= $defaultEnabled ? 'checked' : '' ?>>
                        Habilitado
                    </label>
                </div>
            </div>

            <!-- maxretry -->
            <div class="form-group">
                <label for="maxretry">maxretry
                    <small class="text-muted">(tentativas antes de banir, 1–100)</small>
                </label>
                <input type="number" class="form-control" id="maxretry" name="maxretry"
                       value="<?= $e($defaultMaxretry) ?>" min="1" max="100" required style="width:120px;">
            </div>

            <!-- findtime -->
            <div class="form-group">
                <label for="findtime">findtime
                    <small class="text-muted">(janela em segundos, 60–86400)</small>
                </label>
                <div class="input-group" style="width:200px;">
                    <input type="number" class="form-control" id="findtime" name="findtime"
                           value="<?= $e($defaultFindtime) ?>" min="60" max="86400" required>
                    <span class="input-group-addon">s</span>
                </div>
            </div>

            <!-- bantime -->
            <div class="form-group">
                <label for="bantime">bantime
                    <small class="text-muted">(segundos; -1 = permanente)</small>
                </label>
                <div class="input-group" style="width:200px;">
                    <input type="number" class="form-control" id="bantime" name="bantime"
                           value="<?= $e($defaultBantime) ?>" min="-1" required>
                    <span class="input-group-addon">s</span>
                </div>
            </div>

            <!-- logpath -->
            <div class="form-group">
                <label for="logpath">logpath
                    <small class="text-muted">(caminho absoluto opcional)</small>
                </label>
                <div class="input-group">
                    <input type="text" class="form-control" id="logpath" name="logpath"
                           value="<?= $e($defaultLogpath) ?>"
                           placeholder="/var/log/example.log">
                    <span class="input-group-btn">
                        <button type="button" class="btn btn-default" id="btnValidatePath">Validar</button>
                    </span>
                </div>
                <div id="pathValidationResult" class="amsfb-path-result" style="margin-top:6px;display:none;"></div>
            </div>

            <hr>
            <button type="submit" class="btn btn-primary">Salvar e Recarregar Jail</button>
            <a href="<?= $e($modulelink . '&action=jails') ?>" class="btn btn-default">Cancelar</a>
        </form>
    </div>
</div>

<script>
(function () {
    var btn = document.getElementById('btnValidatePath');
    var res = document.getElementById('pathValidationResult');
    if (!btn || !res) return;

    btn.addEventListener('click', function () {
        var path = document.getElementById('logpath').value.trim();
        if (!path) return;

        btn.disabled = true;
        btn.textContent = '...';
        res.style.display = 'none';

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
            res.style.display = 'block';

            if (!d.success) {
                res.className   = 'amsfb-path-result amsfb-path-error';
                res.textContent = '✗ Erro: ' + (d.error || 'Falha desconhecida');
                return;
            }
            if (d.exists && d.readable) {
                res.className   = 'amsfb-path-result amsfb-path-ok';
                res.textContent = '✓ Arquivo encontrado e legível (' + formatBytes(d.size) + ')';
            } else if (d.exists) {
                res.className   = 'amsfb-path-result amsfb-path-warn';
                res.textContent = '⚠ Arquivo existe mas não é legível pelo processo PHP';
            } else {
                res.className   = 'amsfb-path-result amsfb-path-error';
                res.textContent = '✗ Arquivo não encontrado';
            }
        })
        .catch(function () {
            btn.disabled    = false;
            btn.textContent = 'Validar';
            res.style.display = 'block';
            res.className   = 'amsfb-path-result amsfb-path-warn';
            res.textContent = '⚠ Não foi possível validar (AJAX falhou)';
        });
    });

    function formatBytes(b) {
        if (b < 1024)    return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(2) + ' MB';
    }
})();
</script>
