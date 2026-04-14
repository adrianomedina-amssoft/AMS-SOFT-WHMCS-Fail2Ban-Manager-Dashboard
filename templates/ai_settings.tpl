<?php
/**
 * AI Settings template
 * Disponível: $api_key_set, $ai_mode, $ai_interval, $ai_min_conf,
 *             $ai_whitelist, $ai_prompt, $thresholds, $last_ping_ok
 */
?>

<div class="amsfb-page-header">
    <h3>&#9881; Configurações da IA</h3>
    <a href="<?= $e($modulelink . '&action=ai') ?>" class="btn btn-sm btn-default">&#8592; Sugestões</a>
</div>

<div id="amsfb-settings-result" class="alert" style="display:none;"></div>

<form id="amsfb-settings-form">
<input type="hidden" name="csrf_token" id="amsfb-csrf-settings" value="<?= $e($csrf_token) ?>">

<!-- =========================================================
     Card 0: Bantime Global
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#9201; Bantime Global</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Tempo de banimento padrão</label>
            <select name="global_bantime" class="form-control" style="max-width:260px;">
                <?php
                $bantimeOptions = [
                    604800   => '1 semana',
                    1209600  => '2 semanas',
                    1814400  => '3 semanas',
                    2419200  => '4 semanas',
                    7776000  => '3 meses',
                    15552000 => '6 meses',
                    31536000 => '12 meses',
                ];
                foreach ($bantimeOptions as $val => $label):
                ?>
                <option value="<?= $val ?>" <?= ($global_bantime ?? 604800) === $val ? 'selected' : '' ?>>
                    <?= $e($label) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <span class="help-block">
                Aplicado automaticamente em jails criados pela IA e como valor padrão no modal "Novo Jail".
            </span>
        </div>
    </div>
</div>

<!-- =========================================================
     Card 1: API Anthropic
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128273; Chave API Anthropic</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Chave API</label>
            <div class="input-group">
                <input type="password"
                       id="amsfb-api-key"
                       name="api_key"
                       class="form-control"
                       placeholder="<?= $api_key_set ? '●●●●●●●● (já configurada — preencha para alterar)' : 'sk-ant-...' ?>"
                       autocomplete="new-password">
                <span class="input-group-btn">
                    <button type="button" id="amsfb-ping-btn" class="btn btn-default">
                        &#128268; Testar API
                    </button>
                </span>
            </div>
            <span id="amsfb-ping-result" class="help-block" style="display:none;"></span>
            <?php if ($api_key_set): ?>
            <p class="help-block">
                <span class="label <?= $last_ping_ok === '1' ? 'label-success' : 'label-default' ?>">
                    <?= $last_ping_ok === '1' ? '&#10003; Último ping OK' : '&#9679; Ping não testado' ?>
                </span>
                &nbsp; Chave já configurada. Deixe em branco para manter.
            </p>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- =========================================================
     Card 1b: Modelo de IA
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#129302; Modelo de IA</strong></div>
    <div class="panel-body">
        <div class="form-group">

            <div class="radio">
                <label>
                    <input type="radio" name="ai_model" value="claude-haiku-4-5-20251001"
                        <?= ($ai_model ?? 'claude-haiku-4-5-20251001') === 'claude-haiku-4-5-20251001' ? 'checked' : '' ?>>
                    <strong>Claude Haiku</strong>
                </label>
                <p class="help-block" style="margin-left:20px;">
                    Modelo mais econômico e veloz da família Claude. Excelente para análise de logs de
                    segurança: processa rapidamente grandes volumes de texto com custo muito baixo.
                    <span class="label label-success">&#10003; Recomendado para análise de logs</span>
                </p>
            </div>

            <div class="radio">
                <label>
                    <input type="radio" name="ai_model" value="claude-sonnet-4-6"
                        <?= ($ai_model ?? '') === 'claude-sonnet-4-6' ? 'checked' : '' ?>>
                    <strong>Claude Sonnet</strong>
                </label>
                <p class="help-block" style="margin-left:20px;">
                    Equilíbrio entre capacidade analítica e custo. Ideal quando se deseja maior
                    profundidade na detecção de padrões de ataque sem abrir mão da performance.
                </p>
            </div>

            <div class="radio">
                <label>
                    <input type="radio" name="ai_model" value="claude-opus-4-6"
                        <?= ($ai_model ?? '') === 'claude-opus-4-6' ? 'checked' : '' ?>>
                    <strong>Claude Opus</strong>
                </label>
                <p class="help-block" style="margin-left:20px;">
                    Modelo mais poderoso e preciso. Recomendado apenas para ambientes críticos com
                    alto volume de ataques sofisticados. Custo por análise significativamente mais elevado.
                </p>
            </div>

        </div>
    </div>
</div>

<!-- =========================================================
     Card 1c: Linhas por análise
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128196; Linhas por Análise</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Quantidade de linhas lidas por arquivo de log</label>
            <select name="ai_log_lines" class="form-control" style="max-width:200px;">
                <?php foreach ([200, 400, 600, 800, 1000] as $n): ?>
                <option value="<?= $n ?>" <?= ($ai_log_lines ?? 200) === $n ? 'selected' : '' ?>>
                    <?= $n ?> linhas
                </option>
                <?php endforeach; ?>
            </select>
            <span class="help-block">
                Aplicado tanto na análise automática (cron) quanto ao clicar em "Analisar Agora".
                Valores maiores aumentam a detecção mas elevam o custo de tokens da API.
            </span>
        </div>
    </div>
</div>

<!-- =========================================================
     Card 2: Modo de operação
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#9881; Modo de Operação</strong></div>
    <div class="panel-body">

        <div class="form-group">
            <div class="radio">
                <label>
                    <input type="radio" name="ai_mode" value="suggestion" <?= $ai_mode === 'suggestion' ? 'checked' : '' ?>>
                    <strong>Modo Sugestão</strong> — IA analisa e salva sugestões; admin aprova ou rejeita manualmente.
                </label>
            </div>
            <div class="radio">
                <label>
                    <input type="radio" name="ai_mode" value="auto" id="amsfb-mode-auto" <?= $ai_mode === 'auto' ? 'checked' : '' ?>>
                    <strong>Automático — Banir imediatamente</strong> — IA analisa e executa ban direto, sem aprovação.
                    <span class="label label-danger">Atenção</span>
                </label>
            </div>
            <div class="radio">
                <label>
                    <input type="radio" name="ai_mode" value="threshold" id="amsfb-mode-threshold" <?= $ai_mode === 'threshold' ? 'checked' : '' ?>>
                    <strong>Automático — Threshold configurável</strong> — IA bane somente após N detecções em X minutos.
                </label>
            </div>
        </div>

        <!-- Confirmação para modo automático -->
        <div id="amsfb-auto-confirm" class="alert alert-warning" style="<?= in_array($ai_mode, ['auto', 'threshold']) ? '' : 'display:none;' ?>">
            <label>
                <input type="checkbox" name="confirm_auto" value="1" <?= in_array($ai_mode, ['auto', 'threshold']) ? 'checked' : '' ?>>
                &nbsp;<strong>Confirmo</strong> que entendo que o modo automático executará bans sem aprovação manual.
            </label>
        </div>

        <!-- Sub-formulário threshold -->
        <div id="amsfb-threshold-config" style="<?= $ai_mode === 'threshold' ? '' : 'display:none;' ?>">
            <hr>
            <h5><strong>Configuração de Threshold por Severidade</strong></h5>
            <p class="text-muted">Formato: mínimo de detecções em X minutos antes de banir automaticamente.</p>
            <table class="table table-bordered amsfb-table-sm" style="width:auto;">
                <thead>
                    <tr><th>Severidade</th><th>Detecções mínimas</th><th>Janela (minutos)</th></tr>
                </thead>
                <tbody>
                <?php
                $thresholdDefaults = [
                    'critical' => ['det' => 1, 'min' => 5],
                    'high'     => ['det' => 2, 'min' => 10],
                    'medium'   => ['det' => 5, 'min' => 30],
                ];
                foreach (['critical', 'high', 'medium'] as $sev):
                    $parts = explode(':', $thresholds[$sev] ?? '');
                    $det   = (int)($parts[0] ?? $thresholdDefaults[$sev]['det']);
                    $min   = (int)($parts[1] ?? $thresholdDefaults[$sev]['min']);
                    $sevLabel = ['critical' => 'Crítica', 'high' => 'Alta', 'medium' => 'Média'][$sev];
                ?>
                <tr>
                    <td><span class="amsfb-sev-<?= $e($sev) ?>"><?= $e($sevLabel) ?></span></td>
                    <td>
                        <input type="number" name="threshold_<?= $e($sev) ?>_detections"
                               class="form-control form-control-sm" style="width:80px;"
                               value="<?= $det ?>" min="1" max="100">
                    </td>
                    <td>
                        <input type="number" name="threshold_<?= $e($sev) ?>_minutes"
                               class="form-control form-control-sm" style="width:80px;"
                               value="<?= $min ?>" min="1" max="1440">
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
</div>

<!-- =========================================================
     Card 3: Parâmetros gerais
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128203; Parâmetros Gerais</strong></div>
    <div class="panel-body">

        <div class="form-group">
            <label>Intervalo de análise automática (minutos)</label>
            <select name="ai_interval_minutes" class="form-control" style="width:200px;">
                <?php foreach ([15, 30, 60, 120, 240] as $opt): ?>
                <option value="<?= $opt ?>" <?= ((string)$ai_interval === (string)$opt) ? 'selected' : '' ?>>
                    <?= $opt ?> minutos
                </option>
                <?php endforeach; ?>
            </select>
            <p class="help-block">Usado pelo hook <code>AfterCronJob</code> do WHMCS.</p>
        </div>

        <div class="form-group">
            <label>Confiança mínima para sugerir/banir (%)</label>
            <input type="number" name="ai_min_confidence" class="form-control" style="width:120px;"
                   value="<?= (int)$ai_min_conf ?>" min="0" max="100">
            <p class="help-block">Sugestões abaixo deste valor são ignoradas. Padrão: 75.</p>
        </div>

        <div class="form-group">
            <label>Whitelist de IPs (nunca banir)</label>
            <textarea name="ai_whitelist_ips" class="form-control" rows="4"
                      placeholder="Um IP por linha, ex:&#10;192.168.0.1&#10;10.0.0.1"><?= $e($ai_whitelist) ?></textarea>
            <p class="help-block">Esses IPs nunca serão banidos, mesmo no modo automático.</p>
        </div>

    </div>
</div>

<!-- =========================================================
     Card 4: Prompt customizável
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128172; Prompt enviado ao Claude</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Template do prompt (use <code>{logs}</code> onde as linhas serão inseridas)</label>
            <textarea name="ai_prompt" class="form-control amsfb-prompt-textarea" rows="14"><?= $e($ai_prompt) ?></textarea>
            <p class="help-block">
                Altere para personalizar como o Claude analisa os logs. Use <code>{logs}</code> como placeholder.
            </p>
        </div>
    </div>
</div>

<!-- =========================================================
     Botões de ação
     ========================================================= -->
<div class="amsfb-settings-actions">
    <button type="button" id="amsfb-save-btn" class="btn btn-primary">
        &#10003; Salvar configurações
    </button>
    <button type="button" id="amsfb-run-now-btn" class="btn btn-warning" style="margin-left:8px;">
        &#9654; Rodar análise agora
    </button>
    <span id="amsfb-run-result" class="help-block" style="display:inline-block; margin-left:12px;"></span>
</div>

</form>

<script>
(function () {
    'use strict';

    // Mostrar/ocultar sub-formulários conforme modo selecionado
    var radios = document.querySelectorAll('input[name="ai_mode"]');
    var thresholdDiv  = document.getElementById('amsfb-threshold-config');
    var autoConfirm   = document.getElementById('amsfb-auto-confirm');

    radios.forEach(function (r) {
        r.addEventListener('change', function () {
            if (thresholdDiv) thresholdDiv.style.display = this.value === 'threshold' ? '' : 'none';
            if (autoConfirm)  autoConfirm.style.display  = (this.value === 'auto' || this.value === 'threshold') ? '' : 'none';
        });
    });

    // -------------------------------------------------------------------------
    // Testar API
    // -------------------------------------------------------------------------
    var pingBtn    = document.getElementById('amsfb-ping-btn');
    var pingResult = document.getElementById('amsfb-ping-result');

    if (pingBtn) {
        pingBtn.addEventListener('click', function () {
            var key = document.getElementById('amsfb-api-key').value;
            pingBtn.disabled = true;
            pingBtn.innerHTML = '&#9685; Testando...';
            if (pingResult) { pingResult.style.display = 'none'; }

            window.AMSFB.post('ai', 'ping_api', { api_key: key }, function (data) {
                pingBtn.disabled = false;
                pingBtn.innerHTML = '&#128268; Testar API';
                if (!pingResult) return;
                pingResult.style.display = 'block';
                pingResult.innerHTML = data.success
                    ? '<span class="text-success">&#10003; ' + data.message + '</span>'
                    : '<span class="text-danger">&#10007; ' + (data.error || data.message) + '</span>';
            });
        });
    }

    // -------------------------------------------------------------------------
    // Salvar configurações
    // -------------------------------------------------------------------------
    var saveBtn    = document.getElementById('amsfb-save-btn');
    var resultDiv  = document.getElementById('amsfb-settings-result');

    if (saveBtn) {
        saveBtn.addEventListener('click', function () {
            var form = document.getElementById('amsfb-settings-form');
            var data = {};
            var inputs = form.querySelectorAll('input[name], select[name], textarea[name]');
            inputs.forEach(function (el) {
                if (el.name === 'csrf_token') return; // já incluído pelo AMSFB.post via window.AMSFB.csrfToken
                if (el.type === 'radio' && !el.checked) return;
                if (el.type === 'checkbox') {
                    if (el.checked) data[el.name] = el.value;
                    return;
                }
                data[el.name] = el.value;
            });

            saveBtn.disabled = true;

            window.AMSFB.post('ai', 'save_settings', data, function (resp) {
                saveBtn.disabled = false;
                if (!resultDiv) return;
                resultDiv.style.display = 'block';
                resultDiv.className = resp.success ? 'alert alert-success' : 'alert alert-danger';
                resultDiv.textContent = resp.success ? (resp.message || 'Salvo.') : (resp.error || 'Erro.');
                setTimeout(function () { resultDiv.style.display = 'none'; }, 4000);
            });
        });
    }

    // -------------------------------------------------------------------------
    // Rodar análise agora
    // -------------------------------------------------------------------------
    var runBtn    = document.getElementById('amsfb-run-now-btn');
    var runResult = document.getElementById('amsfb-run-result');

    if (runBtn) {
        runBtn.addEventListener('click', function () {
            if (!confirm('Rodar análise de IA agora em todos os logs configurados?')) return;
            runBtn.disabled = true;
            runBtn.innerHTML = '&#9685; Analisando...';
            if (runResult) runResult.textContent = '';

            window.AMSFB.post('ai', 'run_now', {}, function (data) {
                runBtn.disabled = false;
                runBtn.innerHTML = '&#9654; Rodar análise agora';
                if (!runResult) return;
                runResult.innerHTML = data.success
                    ? '<span class="text-success">&#10003; ' + data.message + '</span>'
                    : '<span class="text-danger">&#10007; ' + (data.error || 'Erro.') + '</span>';
            });
        });
    }

})();
</script>
