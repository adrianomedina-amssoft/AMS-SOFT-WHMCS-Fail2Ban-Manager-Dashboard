<?php
/**
 * AI Settings template — multi-provider
 * Disponível: $active_provider, $providers, $provider_configs,
 *             $ai_mode, $ai_interval, $ai_min_conf, $ai_whitelist,
 *             $ai_prompt, $thresholds, $ai_log_lines, $global_bantime,
 *             $ai_auto_enabled
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
     Card 1: Provedor de IA Ativo
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#129302; Provedor de IA Ativo</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <p class="help-block">Selecione qual provedor de IA será usado para análise de logs. Apenas 1 provedor ativo por vez.</p>
            <?php foreach ($providers as $key => $def): ?>
            <div class="radio">
                <label>
                    <input type="radio" name="ai_active_provider" value="<?= $e($key) ?>"
                        <?= ($active_provider === $key) ? 'checked' : '' ?>
                        data-provider-toggle="<?= $e($key) ?>">
                    <strong><?= $e($def['label']) ?></strong>
                    <?php if ($key === 'anthropic'): ?>
                        <span class="label label-info" style="margin-left:6px;">Protocolo Anthropic</span>
                    <?php elseif (!empty($def['has_protocol_selector'])): ?>
                        <span class="label label-default" style="margin-left:6px;">Anthropic / OpenAI</span>
                    <?php else: ?>
                        <span class="label label-default" style="margin-left:6px;">Protocolo <?= $e($def['protocol']) ?></span>
                    <?php endif; ?>
                </label>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<!-- =========================================================
     Card 2: Configurações por Provedor
     ========================================================= -->
<?php foreach ($providers as $key => $def): ?>
<?php $pcfg = $provider_configs[$key]; ?>
<div class="panel panel-default amsfb-provider-panel" id="amsfb-provider-<?= $e($key) ?>"
     style="<?= ($active_provider !== $key) ? 'display:none;' : '' ?>">
    <div class="panel-heading">
        <strong><?= $e($def['label']) ?> — Configurações</strong>
        <?php if ($active_provider === $key): ?>
            <span class="label label-success pull-right">&#10003; Ativo</span>
        <?php endif; ?>
    </div>
    <div class="panel-body">

        <!-- Chave API -->
        <div class="form-group">
            <label>Chave API</label>
            <div class="input-group">
                <input type="password"
                       name="ai_provider_<?= $e($key) ?>_api_key"
                       class="form-control amsfb-api-key"
                       data-provider="<?= $e($key) ?>"
                       placeholder="<?= $pcfg['api_key_set'] ? '●●●●●●●● (já configurada — preencha para alterar)' : 'Insira sua chave API...' ?>"
                       autocomplete="new-password">
                <span class="input-group-btn">
                    <button type="button" class="btn btn-default amsfb-ping-btn" data-provider="<?= $e($key) ?>">
                        &#128268; Testar API
                    </button>
                </span>
            </div>
            <span class="amsfb-ping-result help-block" style="display:none;" data-provider="<?= $e($key) ?>"></span>
            <?php if ($pcfg['api_key_set']): ?>
            <p class="help-block">
                <span class="label <?= $pcfg['last_ping'] === '1' ? 'label-success' : 'label-default' ?>">
                    <?= $pcfg['last_ping'] === '1' ? '&#10003; Último ping OK' : '&#9679; Ping não testado' ?>
                </span>
                &nbsp; Chave já configurada. Deixe em branco para manter.
            </p>
            <?php endif; ?>
        </div>

        <?php if (!empty($def['has_protocol_selector'])): ?>
        <!-- Seletor de protocolo (ex: MiMo Anthropic vs OpenAI) -->
        <div class="form-group">
            <label>Protocolo da API</label>
            <?php
            $savedProtocol = $provider_configs[$key]['protocol'] ?? $def['protocol'];
            foreach ($def['protocol_options'] as $protoKey => $protoDef):
            ?>
            <div class="radio">
                <label>
                    <input type="radio" name="ai_provider_<?= $e($key) ?>_protocol" value="<?= $e($protoKey) ?>"
                        <?= ($savedProtocol === $protoKey) ? 'checked' : '' ?>>
                    <strong><?= $e($protoDef['label']) ?></strong>
                    <span class="help-block" style="margin:0;">
                        <code><?= $e($protoDef['base_url']) ?></code>
                    </span>
                </label>
            </div>
            <?php endforeach; ?>
            <span class="help-block">
                Escolha o protocolo compatível com sua chave API.
            </span>
        </div>
        <?php endif; ?>

        <?php if ($def['needs_base_url']): ?>
        <!-- Base URL (apenas para provedores editáveis) -->
        <div class="form-group">
            <label>Base URL</label>
            <input type="url"
                   name="ai_provider_<?= $e($key) ?>_base_url"
                   class="form-control"
                   value="<?= $e($pcfg['base_url']) ?>"
                   placeholder="<?= $e($def['default_base_url']) ?>">
            <span class="help-block">
                Endpoint da API. Default: <code><?= $e($def['default_base_url']) ?></code>
            </span>
        </div>
        <?php endif; ?>

        <!-- Modelo -->
        <div class="form-group">
            <label>Modelo</label>
            <?php foreach ($def['models'] as $modelId => $modelLabel): ?>
            <div class="radio">
                <label>
                    <input type="radio" name="ai_provider_<?= $e($key) ?>_model" value="<?= $e($modelId) ?>"
                        <?= ($pcfg['model'] === $modelId) ? 'checked' : '' ?>>
                    <strong><?= $e($modelLabel) ?></strong>
                </label>
            </div>
            <?php endforeach; ?>
        </div>

    </div>
</div>
<?php endforeach; ?>

<!-- =========================================================
     Card 3: Linhas por análise
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
     Card 4: Modo de operação
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#9881; Modo de Operação</strong></div>
    <div class="panel-body">

        <!-- Toggle análise automática -->
        <div class="form-group">
            <label>
                <input type="checkbox" name="ai_auto_enabled" value="1"
                       id="amsfb-auto-enabled"
                       <?= ($ai_auto_enabled === '1') ? 'checked' : '' ?>>
                &nbsp;<strong>Ativar análise automática (via cron do WHMCS)</strong>
            </label>
            <p class="help-block">
                Quando desativado, a IA só analisará logs quando você clicar manualmente em
                <strong>"Analisar com IA"</strong> nas páginas
                <a href="<?= $modulelink ?>&action=ai">Sugestões de IA</a> ou
                <a href="<?= $modulelink ?>&action=logviewer">Log Viewer</a>.
            </p>
        </div>
        <div id="amsfb-auto-disabled-warning" class="alert alert-info"
             style="<?= ($ai_auto_enabled !== '1') ? '' : 'display:none;' ?>">
            &#8505; Análise automática <strong>desativada</strong>. O cron do WHMCS não disparará análises de IA.
        </div>
        <hr>

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
     Card 5: Parâmetros gerais
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
     Card 6: Prompt customizável (compartilhado)
     ========================================================= -->
<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128172; Prompt enviado à IA</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Template do prompt (use <code>{logs}</code> onde as linhas serão inseridas)</label>
            <textarea name="ai_prompt" class="form-control amsfb-prompt-textarea" rows="14"><?= $e($ai_prompt) ?></textarea>
            <p class="help-block">
                Altere para personalizar como a IA analisa os logs. Use <code>{logs}</code> como placeholder.
                Este prompt é compartilhado entre todos os provedores.
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

<!-- =========================================================
     Seção: GeoIP
     ========================================================= -->
<div class="panel panel-default" style="margin-top:24px;">
    <div class="panel-heading"><strong>&#127757; GeoIP — Dados Geográficos</strong></div>
    <div class="panel-body">
        <p class="text-muted" style="margin-bottom:12px;">
            Dados geográficos dos IPs exibidos na interface (país, estado, ISP).
            Powered by <a href="https://ip-api.com/" target="_blank">ip-api.com</a> (gratuito, sem chave).
        </p>
        <div class="row">
            <div class="col-sm-6">
                <p><strong>Status da API:</strong> <span id="amsfb-geoip-status">—</span></p>
                <p><strong>Requests este minuto:</strong> <span id="amsfb-geoip-rate">—</span></p>
            </div>
            <div class="col-sm-6">
                <button type="button" id="amsfb-ping-geoip" class="btn btn-sm btn-primary">
                    &#128270; Testar conexão
                </button>
                <button type="button" id="amsfb-clear-geoip" class="btn btn-sm btn-default" style="margin-left:8px;">
                    &#128465; Limpar cache geo
                </button>
                <span id="amsfb-geoip-result" class="help-block" style="display:block; margin-top:8px;"></span>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // Toggle provedor ativo — mostra/esconde seções
    // -------------------------------------------------------------------------
    var providerRadios = document.querySelectorAll('input[name="ai_active_provider"]');
    var providerPanels = document.querySelectorAll('.amsfb-provider-panel');

    function toggleProviderPanels(activeProvider) {
        providerPanels.forEach(function (panel) {
            panel.style.display = panel.id === 'amsfb-provider-' + activeProvider ? '' : 'none';
        });
    }

    providerRadios.forEach(function (r) {
        r.addEventListener('change', function () {
            toggleProviderPanels(this.value);
        });
    });

    // Toggle análise automática
    var autoEnabledChk = document.getElementById('amsfb-auto-enabled');
    var autoDisabledWarn = document.getElementById('amsfb-auto-disabled-warning');
    if (autoEnabledChk) {
        autoEnabledChk.addEventListener('change', function () {
            if (autoDisabledWarn) autoDisabledWarn.style.display = this.checked ? 'none' : '';
        });
    }

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
    // Testar API (multi-provider)
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-ping-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var provider = this.getAttribute('data-provider');
            var keyInput = document.querySelector('.amsfb-api-key[data-provider="' + provider + '"]');
            var resultSpan = document.querySelector('.amsfb-ping-result[data-provider="' + provider + '"]');
            var key = keyInput ? keyInput.value : '';

            // Capturar protocolo se o provedor tem seletor
            var protoRadio = document.querySelector('input[name="ai_provider_' + provider + '_protocol"]:checked');
            var protocol = protoRadio ? protoRadio.value : '';

            btn.disabled = true;
            btn.innerHTML = '&#9685; Testando...';
            if (resultSpan) resultSpan.style.display = 'none';

            window.AMSFB.post('ai', 'ping_api', { provider: provider, api_key: key, protocol: protocol }, function (data) {
                btn.disabled = false;
                btn.innerHTML = '&#128268; Testar API';
                if (!resultSpan) return;
                resultSpan.style.display = 'block';
                resultSpan.innerHTML = data.success
                    ? '<span class="text-success">&#10003; ' + data.message + '</span>'
                    : '<span class="text-danger">&#10007; ' + (data.error || data.message) + '</span>';
            });
        });
    });

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
                if (el.name === 'csrf_token') return;
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

    // -------------------------------------------------------------------------
    // GeoIP: testar conexão
    // -------------------------------------------------------------------------
    var pingGeoBtn = document.getElementById('amsfb-ping-geoip');
    var geoipStatus = document.getElementById('amsfb-geoip-status');
    var geoipRate = document.getElementById('amsfb-geoip-rate');
    var geoipResult = document.getElementById('amsfb-geoip-result');

    if (pingGeoBtn) {
        pingGeoBtn.addEventListener('click', function () {
            pingGeoBtn.disabled = true;
            pingGeoBtn.innerHTML = '&#9685; Testando...';
            if (geoipResult) geoipResult.textContent = '';

            window.AMSFB.post('ai', 'ping_geoip', {}, function (data) {
                pingGeoBtn.disabled = false;
                pingGeoBtn.innerHTML = '&#128270; Testar conexão';
                if (geoipStatus) {
                    geoipStatus.innerHTML = data.success
                        ? '<span class="text-success">&#10003; Conectado</span>'
                        : '<span class="text-danger">&#10007; Indisponível</span>';
                }
                if (geoipRate && data.status) {
                    var rateText = data.status.requests_this_minute + ' / 40 (restam ' + data.status.requests_remaining + ')';
                    if (data.status.in_cooldown) {
                        rateText += ' — COOLDOWN ATIVO (429 recebido)';
                    }
                    geoipRate.textContent = rateText;
                }
                if (geoipResult) {
                    geoipResult.innerHTML = data.success
                        ? '<span class="text-success">' + data.message + '</span>'
                        : '<span class="text-danger">' + (data.message || 'Erro.') + '</span>';
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // GeoIP: limpar cache
    // -------------------------------------------------------------------------
    var clearGeoBtn = document.getElementById('amsfb-clear-geoip');
    if (clearGeoBtn) {
        clearGeoBtn.addEventListener('click', function () {
            if (!confirm('Limpar todo o cache de dados geo? IPs serão re-consultados na próxima visita.')) return;
            clearGeoBtn.disabled = true;
            clearGeoBtn.innerHTML = '&#9685; Limpando...';

            window.AMSFB.post('ai', 'clear_geoip_cache', {}, function (data) {
                clearGeoBtn.disabled = false;
                clearGeoBtn.innerHTML = '&#128465; Limpar cache geo';
                if (geoipResult) {
                    geoipResult.innerHTML = data.success
                        ? '<span class="text-success">&#10003; ' + data.message + '</span>'
                        : '<span class="text-danger">&#10007; ' + (data.error || 'Erro.') + '</span>';
                }
            });
        });
    }

})();
</script>
