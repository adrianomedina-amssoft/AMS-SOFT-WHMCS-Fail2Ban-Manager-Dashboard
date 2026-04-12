<?php
/**
 * Log Paths template
 * Available: $auto_logs (array), $custom_logs (array)
 * auto_logs:   [['label','path','readable','size'], ...]
 * custom_logs: [['key','label','path','readable','size'], ...]
 */
?>

<div class="amsfb-page-header">
    <h3>&#128196; Log Paths</h3>
</div>

<p class="text-muted">
    Gerencie os arquivos de log exibidos no <strong>Log Viewer</strong>.
    Os logs detectados automaticamente aparecem sem configuração;
    use o formulário abaixo para adicionar caminhos extras.
</p>

<!-- =========================================================
     Formulário: Adicionar log customizado
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#10133; Adicionar Log Personalizado</strong></div>
    <div class="panel-body">
        <form method="post" action="<?= $e($modulelink . '&action=logpaths') ?>" class="form-inline">
            <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
            <input type="hidden" name="do" value="add">

            <div class="form-group" style="margin-right:8px;">
                <label class="sr-only">Label</label>
                <input type="text" name="label" id="amsfb-new-label"
                       class="form-control" placeholder="Label (ex: Meu App)"
                       maxlength="64" style="width:180px;" required>
            </div>

            <div class="form-group" style="margin-right:8px;">
                <label class="sr-only">Path</label>
                <input type="text" name="path" id="amsfb-new-path"
                       class="form-control" placeholder="/var/log/meuapp.log"
                       style="width:320px;" required>
            </div>

            <button type="button" id="amsfb-validate-new" class="btn btn-default" style="margin-right:4px;">
                &#10003; Validar
            </button>
            <button type="submit" class="btn btn-primary">
                &#10133; Adicionar
            </button>

            <span id="amsfb-new-val-result" style="margin-left:10px;"></span>
        </form>
    </div>
</div>

<!-- =========================================================
     Seção 1: Logs auto-detectados
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading">
        <strong>&#128269; Logs Detectados Automaticamente</strong>
        <small class="text-muted" style="margin-left:8px;">Somente leitura — nenhuma configuração necessária</small>
    </div>

    <?php if (empty($auto_logs)): ?>
    <div class="panel-body text-muted">Nenhum log conhecido encontrado no disco.</div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-striped amsfb-table" style="margin-bottom:0;">
            <thead>
                <tr>
                    <th style="width:200px;">Label</th>
                    <th>Path</th>
                    <th style="width:120px;">Leitura</th>
                    <th style="width:80px;">Tamanho</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($auto_logs as $log): ?>
                <tr>
                    <td><?= $e($log['label']) ?> <span class="label label-default" style="font-size:10px;">auto</span></td>
                    <td><code><?= $e($log['path']) ?></code></td>
                    <td>
                        <?php if ($log['readable']): ?>
                        <span class="text-success">&#10003; Legível</span>
                        <?php else: ?>
                        <span class="text-warning">&#9888; Sem permissão</span>
                        <?php endif; ?>
                    </td>
                    <td class="text-muted"><?= $e(\AMS\Fail2Ban\Helper::fmtBytes((int)$log['size'])) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<!-- =========================================================
     Seção 2: Logs personalizados
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128221; Logs Personalizados</strong></div>

    <?php if (empty($custom_logs)): ?>
    <div class="panel-body text-muted">Nenhum log personalizado adicionado ainda.</div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-striped amsfb-table" style="margin-bottom:0;">
            <thead>
                <tr>
                    <th style="width:200px;">Label</th>
                    <th>Path</th>
                    <th style="width:120px;">Leitura</th>
                    <th style="width:80px;">Tamanho</th>
                    <th style="width:100px;">Ação</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($custom_logs as $log): ?>
                <tr>
                    <td><?= $e($log['label']) ?></td>
                    <td><code><?= $e($log['path']) ?></code></td>
                    <td>
                        <?php if ($log['readable']): ?>
                        <span class="text-success">&#10003; Legível</span>
                        <?php else: ?>
                        <span class="text-warning">&#9888; Sem permissão</span>
                        <?php endif; ?>
                    </td>
                    <td class="text-muted"><?= $e(\AMS\Fail2Ban\Helper::fmtBytes((int)$log['size'])) ?></td>
                    <td>
                        <form method="post" action="<?= $e($modulelink . '&action=logpaths') ?>"
                              style="display:inline;"
                              onsubmit="return confirm('Remover log \'<?= $e(addslashes($log['label'])) ?>\'?')">
                            <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
                            <input type="hidden" name="do"  value="delete">
                            <input type="hidden" name="key" value="<?= $e($log['key']) ?>">
                            <button type="submit" class="btn btn-xs btn-danger">&#10005; Remover</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<script>
(function () {
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

    // Botão Validar (formulário de adição)
    var validateBtn = document.getElementById('amsfb-validate-new');
    var pathInput   = document.getElementById('amsfb-new-path');
    var valResult   = document.getElementById('amsfb-new-val-result');

    if (validateBtn && pathInput && valResult) {
        validateBtn.addEventListener('click', function () {
            var path = pathInput.value.trim();
            if (!path) return;

            validateBtn.disabled    = true;
            validateBtn.textContent = '...';
            valResult.innerHTML     = '<span class="text-muted">Verificando...</span>';

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
                if (d.csrf_token) {
                    window.AMSFB.csrfToken = d.csrf_token;
                    var inp = validateBtn.closest('form').querySelector('input[name="csrf_token"]');
                    if (inp) { inp.value = d.csrf_token; }
                }
                validateBtn.disabled    = false;
                validateBtn.textContent = '✓ Validar';

                if (!d.success) {
                    valResult.innerHTML = '<span class="text-danger">&#10007; ' + escHtml(d.error || 'Erro') + '</span>';
                    return;
                }
                if (d.exists && d.readable) {
                    valResult.innerHTML = '<span class="text-success">&#10003; Legível (' + formatBytes(d.size) + ')</span>';
                } else if (d.exists) {
                    valResult.innerHTML = '<span class="text-warning">&#9888; Arquivo existe mas sem permissão de leitura</span>';
                } else {
                    valResult.innerHTML = '<span class="text-danger">&#10007; Arquivo não encontrado</span>';
                }
            })
            .catch(function () {
                validateBtn.disabled    = false;
                validateBtn.textContent = '✓ Validar';
                valResult.innerHTML = '<span class="text-warning">&#9888; Falha na requisição</span>';
            });
        });
    }
})();
</script>
