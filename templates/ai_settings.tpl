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
                    <span class="label label-default" style="margin-left:6px;">Protocolo <?= $e(ucfirst($def['protocol'])) ?></span>
                </label>
            </div>
            <?php endforeach; ?>
        </div>
        <div id="amsfb-mimo-security-warning" class="alert alert-warning" style="display:none; margin-top:10px;">
            <strong>⚠️ Aviso de segurança:</strong> Este provedor tem resistência reduzida a certas técnicas de manipulação de log (prompt injection).
            Recomendamos manter a heurística de fallback ativa — ela é a defesa primária contra evasão de detecção para este provedor.
            Para máxima proteção, considere usar Anthropic.
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

<div class="panel panel-default">
    <div class="panel-heading"><strong>&#128260; Lotes por Sessão de Análise</strong></div>
    <div class="panel-body">
        <div class="form-group">
            <label>Máximo de lotes por sessão</label>
            <select name="ai_batch_max_per_session" class="form-control" style="max-width:200px;">
                <?php foreach ([10, 20, 50, 100] as $n): ?>
                <option value="<?= $n ?>" <?= ($ai_batch_max_per_session ?? 20) === $n ? 'selected' : '' ?>>
                    <?= $n ?> lotes
                </option>
                <?php endforeach; ?>
            </select>
            <span class="help-block">
                Quantidade máxima de chamadas à IA por log numa única sessão de análise.
                1 lote = ai_log_lines linhas. Quando atingido, o restante é processado na próxima sessão (cron ou manual).
                <br><strong>Default: 20</strong> — conservador para não monopolizar tokens em logs atípicos.
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

        <!-- Auto-criar filtro/jail (Auto e Threshold) -->
        <div id="amsfb-auto-filter-opt" style="<?= in_array($ai_mode, ['auto', 'threshold']) ? '' : 'display:none;' ?>">
            <hr>
            <label>
                <input type="checkbox" name="ai_auto_create_filter" value="1"
                       <?= ($ai_auto_create_filter ?? '0') === '1' ? 'checked' : '' ?>>
                &nbsp;<strong>Criar filtro/jail automaticamente quando o padrão se repetir</strong>
            </label>
            <p class="help-block">
                A IA cria um filtro fail2ban específico para o tipo de ataque e bane na jail
                correspondente (ex: amsfb-apache-scan) em vez da jail genérica ai-bans.
                O filtro só é criado depois que o mesmo padrão aparece N vezes com IPs diferentes,
                garantindo que o regex generalize bem e não seja overfit para um único atacante.
            </p>
            <div style="margin-left:24px; margin-top:8px;">
                <div style="margin-bottom:6px;">
                    <label>Mínimo de ocorrências do padrão:</label>
                    <input type="number" name="ai_auto_create_min_occurrences"
                           value="<?= $e((int)($ai_auto_create_min_occurrences ?? 3)) ?>"
                           min="2" max="50" class="form-control form-control-sm"
                           style="display:inline-block; width:60px;">
                    <span class="text-muted">(padrão: 3)</span>
                </div>
                <div style="margin-bottom:6px;">
                    <label>Mínimo de IPs distintos:</label>
                    <input type="number" name="ai_auto_create_min_distinct_ips"
                           value="<?= $e((int)($ai_auto_create_min_distinct_ips ?? 2)) ?>"
                           min="1" max="20" class="form-control form-control-sm"
                           style="display:inline-block; width:60px;">
                    <span class="text-muted">(padrão: 2)</span>
                    <span class="help-block" style="display:block; margin-top:2px;">
                        Exige IPs diferentes para provar que o padrão generaliza (não é overfit para um único atacante).
                    </span>
                </div>
                <div style="margin-bottom:6px;">
                    <label>Janela de tempo (dias):</label>
                    <input type="number" name="ai_auto_create_window_days"
                           value="<?= $e((int)($ai_auto_create_window_days ?? 30)) ?>"
                           min="1" max="365" class="form-control form-control-sm"
                           style="display:inline-block; width:60px;">
                    <span class="text-muted">(padrão: 30)</span>
                </div>
                <div>
                    <label>Limite de jails auto-criadas por dia:</label>
                    <input type="number" name="ai_auto_max_jails_per_day"
                           value="<?= $e((int)($ai_auto_max_jails_per_day ?? 5)) ?>"
                           min="1" max="50" class="form-control form-control-sm"
                           style="display:inline-block; width:60px;">
                </div>
            </div>
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
        // Aviso de segurança para MiMo
        var mimoWarning = document.getElementById('amsfb-mimo-security-warning');
        if (mimoWarning) {
            mimoWarning.style.display = activeProvider === 'mimo' ? 'block' : 'none';
        }
    }

    providerRadios.forEach(function (r) {
        r.addEventListener('change', function () {
            toggleProviderPanels(this.value);
        });
    });

    // Inicializar: mostrar aviso se MiMo já estiver selecionado
    var checkedProvider = document.querySelector('input[name="ai_active_provider"]:checked');
    if (checkedProvider) {
        toggleProviderPanels(checkedProvider.value);
    }

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
    var autoFilterOpt = document.getElementById('amsfb-auto-filter-opt');

    radios.forEach(function (r) {
        r.addEventListener('change', function () {
            if (thresholdDiv)  thresholdDiv.style.display  = this.value === 'threshold' ? '' : 'none';
            if (autoConfirm)   autoConfirm.style.display   = (this.value === 'auto' || this.value === 'threshold') ? '' : 'none';
            if (autoFilterOpt) autoFilterOpt.style.display = (this.value === 'auto' || this.value === 'threshold') ? '' : 'none';
        });
    });

    // Habilitar/desabilitar sub-campos de auto-create conforme checkbox
    var autoCreateCb = document.querySelector('input[name="ai_auto_create_filter"]');
    var autoFilterSubfields = autoFilterOpt
        ? autoFilterOpt.querySelectorAll('input[type="number"]')
        : [];
    function toggleAutoCreateSubfields() {
        var on = autoCreateCb && autoCreateCb.checked;
        autoFilterSubfields.forEach(function (f) { f.disabled = !on; });
    }
    if (autoCreateCb) {
        autoCreateCb.addEventListener('change', toggleAutoCreateSubfields);
        toggleAutoCreateSubfields(); // estado inicial
    }

    // -------------------------------------------------------------------------
    // Testar API (multi-provider)
    // -------------------------------------------------------------------------
    document.querySelectorAll('.amsfb-ping-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var provider = this.getAttribute('data-provider');
            var keyInput = document.querySelector('.amsfb-api-key[data-provider="' + provider + '"]');
            var resultSpan = document.querySelector('.amsfb-ping-result[data-provider="' + provider + '"]');
            var key = keyInput ? keyInput.value : '';

            btn.disabled = true;
            btn.innerHTML = '&#9685; Testando...';
            if (resultSpan) resultSpan.style.display = 'none';

            window.AMSFB.post('ai', 'ping_api', { provider: provider, api_key: key }, function (data) {
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
