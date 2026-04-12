<?php
/**
 * Log Viewer template
 * Disponível: $available_logs (array de ['label'=>jail, 'path'=>caminho])
 */
?>

<div class="amsfb-page-header">
    <h3>&#128220; Log Viewer</h3>
    <span class="amsfb-badge-mode">Tempo real</span>
</div>

<?php if (empty($available_logs)): ?>
<div class="alert alert-warning">
    Nenhum log configurado. Configure os paths em
    <a href="<?= $e($modulelink . '&action=logpaths') ?>">Log Paths</a>.
</div>
<?php else: ?>

<!-- Barra de controles -->
<div class="amsfb-logviewer-controls">
    <div class="row">
        <div class="col-sm-4">
            <label class="amsfb-label-sm">Log</label>
            <select id="amsfb-log-select" class="form-control form-control-sm">
                <?php foreach ($available_logs as $log): ?>
                <option value="<?= $e($log['path']) ?>"><?= $e($log['label']) ?> — <?= $e($log['path']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="col-sm-2">
            <label class="amsfb-label-sm">Linhas</label>
            <select id="amsfb-log-lines" class="form-control form-control-sm">
                <option value="50">50</option>
                <option value="100" selected>100</option>
                <option value="200">200</option>
                <option value="500">500</option>
            </select>
        </div>
        <div class="col-sm-3">
            <label class="amsfb-label-sm">Filtro (IP ou termo)</label>
            <input type="text" id="amsfb-log-filter" class="form-control form-control-sm" placeholder="Filtrar...">
        </div>
        <div class="col-sm-3" style="padding-top:22px;">
            <button id="amsfb-btn-refresh" class="btn btn-sm btn-default" title="Atualizar agora">
                &#8635; Atualizar
            </button>
            <button id="amsfb-btn-pause" class="btn btn-sm btn-warning">
                &#9646;&#9646; Pausar
            </button>
            <button id="amsfb-btn-analyze" class="btn btn-sm btn-primary" title="Enviar log atual para análise da IA">
                &#129302; Analisar com IA
            </button>
        </div>
    </div>
</div>

<!-- Legenda -->
<div class="amsfb-log-legend">
    <span class="amsfb-log-badge-error">&#9632; Erro/Ban</span>
    <span class="amsfb-log-badge-suspicious">&#9632; Suspeito</span>
    <span class="amsfb-log-badge-normal">&#9632; Normal</span>
    &nbsp;&nbsp;
    <span id="amsfb-log-status" class="text-muted" style="font-size:12px;">Carregando...</span>
    &nbsp;
    <span id="amsfb-log-count" class="text-muted" style="font-size:12px;"></span>
</div>

<!-- Área do log -->
<div class="amsfb-log-container" id="amsfb-log-output">
    <div class="amsfb-log-loading">&#9685; Carregando linhas...</div>
</div>

<!-- Resultado da análise IA (aparece após clicar "Analisar com IA") -->
<div id="amsfb-analyze-result" class="alert" style="display:none; margin-top:12px;"></div>

<!-- Modais de ban inline -->
<div class="modal fade" id="amsfb-ban-modal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-sm" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">Banir IP</h4>
            </div>
            <div class="modal-body">
                <p>Banir <strong id="amsfb-ban-ip-display"></strong>?</p>
                <label>Jail</label>
                <input type="text" id="amsfb-ban-jail-input" class="form-control" placeholder="sshd">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancelar</button>
                <button type="button" class="btn btn-danger" id="amsfb-ban-confirm">Banir</button>
            </div>
        </div>
    </div>
</div>

<?php endif; ?>

<script>
(function () {
    'use strict';

    var SELECT   = document.getElementById('amsfb-log-select');
    var LINES    = document.getElementById('amsfb-log-lines');
    var FILTER   = document.getElementById('amsfb-log-filter');
    var OUTPUT   = document.getElementById('amsfb-log-output');
    var STATUS   = document.getElementById('amsfb-log-status');
    var COUNT    = document.getElementById('amsfb-log-count');
    var RESULT   = document.getElementById('amsfb-analyze-result');

    if (!SELECT || !OUTPUT) return;

    var paused   = false;
    var interval = null;
    var banIp    = '';

    // -------------------------------------------------------------------------
    // Fetch lines via AJAX
    // -------------------------------------------------------------------------
    function fetchLines() {
        if (paused) return;
        var path  = SELECT.value;
        var lines = LINES ? LINES.value : '100';

        STATUS.textContent = 'Atualizando...';

        window.AMSFB.post('logviewer', 'fetch_lines', { path: path, lines: lines }, function (data) {
            if (!data.success) {
                STATUS.textContent = 'Erro: ' + (data.error || 'desconhecido');
                return;
            }
            renderLines(data.lines || []);
            COUNT.textContent = (data.total || 0) + ' linhas';
            STATUS.textContent = 'Atualizado: ' + new Date().toLocaleTimeString();
        });
    }

    // -------------------------------------------------------------------------
    // Render lines with highlighting and IP buttons
    // -------------------------------------------------------------------------
    function renderLines(lines) {
        var filter = FILTER ? FILTER.value.toLowerCase() : '';
        var html   = '';

        lines.forEach(function (item) {
            var text  = item.text  || '';
            var cls   = item.class || 'normal';
            var ips   = item.ips  || [];

            if (filter && text.toLowerCase().indexOf(filter) === -1) return;

            var lineCls = 'amsfb-log-line amsfb-log-' + cls;

            // Escapar HTML
            var escaped = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

            // Botões de ban inline para cada IP
            var ipBtns = '';
            ips.forEach(function (ip) {
                ipBtns += '<button class="amsfb-inline-ban btn btn-xs btn-danger" data-ip="' + ip + '" title="Banir ' + ip + '">&#128683; ' + ip + '</button> ';
            });

            html += '<div class="' + lineCls + '">' + (ipBtns ? '<span class="amsfb-ip-btns">' + ipBtns + '</span>' : '') + '<code>' + escaped + '</code></div>';
        });

        OUTPUT.innerHTML = html || '<div class="amsfb-log-empty">Nenhuma linha corresponde ao filtro.</div>';

        // Scroll para o final
        OUTPUT.scrollTop = OUTPUT.scrollHeight;

        // Attach ban button listeners
        OUTPUT.querySelectorAll('.amsfb-inline-ban').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openBanModal(this.getAttribute('data-ip'));
            });
        });
    }

    // -------------------------------------------------------------------------
    // Auto-refresh
    // -------------------------------------------------------------------------
    function startRefresh() {
        if (interval) clearInterval(interval);
        interval = setInterval(fetchLines, 5000);
    }

    function stopRefresh() {
        if (interval) clearInterval(interval);
        interval = null;
    }

    // Botão Pausar / Retomar
    var pauseBtn = document.getElementById('amsfb-btn-pause');
    if (pauseBtn) {
        pauseBtn.addEventListener('click', function () {
            paused = !paused;
            this.innerHTML = paused ? '&#9654; Retomar' : '&#9646;&#9646; Pausar';
            this.className = paused ? 'btn btn-sm btn-success' : 'btn btn-sm btn-warning';
        });
    }

    // Botão Atualizar
    var refreshBtn = document.getElementById('amsfb-btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function () { fetchLines(); });
    }

    // Mudança de log / linhas
    if (SELECT) SELECT.addEventListener('change', function () { fetchLines(); });
    if (LINES)  LINES.addEventListener('change',  function () { fetchLines(); });

    // Filtro client-side
    if (FILTER) {
        FILTER.addEventListener('input', function () {
            // Re-renderiza com o filtro atual (re-usa último resultado)
            fetchLines();
        });
    }

    // -------------------------------------------------------------------------
    // Analisar com IA
    // -------------------------------------------------------------------------
    var analyzeBtn = document.getElementById('amsfb-btn-analyze');
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', function () {
            var path  = SELECT.value;
            var lines = LINES ? LINES.value : '100';

            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '&#9685; Analisando...';

            if (RESULT) {
                RESULT.style.display = 'none';
                RESULT.className = 'alert';
            }

            window.AMSFB.post('logviewer', 'analyze', { path: path, lines: lines }, function (data) {
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '&#129302; Analisar com IA';

                if (!RESULT) return;
                RESULT.style.display = 'block';

                if (data.success) {
                    RESULT.className = 'alert alert-success';
                    RESULT.innerHTML = '&#10003; ' + (data.message || 'Análise concluída.') +
                        ' <a href="<?= $e($modulelink . '&action=ai') ?>">Ver sugestões &rarr;</a>';
                } else {
                    RESULT.className = 'alert alert-danger';
                    RESULT.innerHTML = '&#10007; ' + (data.error || 'Erro desconhecido.');
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Modal de ban
    // -------------------------------------------------------------------------
    function openBanModal(ip) {
        banIp = ip;
        var display = document.getElementById('amsfb-ban-ip-display');
        if (display) display.textContent = ip;
        var jailInput = document.getElementById('amsfb-ban-jail-input');
        if (jailInput) jailInput.value = '';
        if (typeof $ !== 'undefined') {
            $('#amsfb-ban-modal').modal('show');
        }
    }

    var banConfirm = document.getElementById('amsfb-ban-confirm');
    if (banConfirm) {
        banConfirm.addEventListener('click', function () {
            var jail = (document.getElementById('amsfb-ban-jail-input') || {}).value || '';
            window.AMSFB.post('logviewer', 'ban_ip', { ip: banIp, jail: jail }, function (data) {
                if (typeof $ !== 'undefined') $('#amsfb-ban-modal').modal('hide');
                if (data.success) {
                    alert('✓ ' + data.message);
                } else {
                    alert('✗ ' + (data.error || data.message || 'Erro ao banir.'));
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Inicializar
    // -------------------------------------------------------------------------
    fetchLines();
    startRefresh();

})();
</script>
