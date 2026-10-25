(function () {
    'use strict';
    var root = document.getElementById('amsfb-protection');
    if (!root) return;
    var form = document.getElementById('amsfb-policy');
    var tabs = Array.from(root.querySelectorAll('[role="tab"]'));
    function selectTab(tab, focus) {
        tabs.forEach(function (item) {
            var selected = item === tab;
            item.setAttribute('aria-selected', selected ? 'true' : 'false');
            item.tabIndex = selected ? 0 : -1;
            item.parentElement.classList.toggle('active', selected);
            var panel = document.getElementById(item.getAttribute('aria-controls'));
            panel.hidden = !selected;
            panel.classList.toggle('active', selected);
        });
        if (focus) tab.focus();
    }
    tabs.forEach(function (tab, index) {
        tab.addEventListener('click', function (event) { event.preventDefault(); event.stopPropagation(); selectTab(tab, false); });
        tab.addEventListener('keydown', function (event) {
            var next = index;
            if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
            else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
            else if (event.key === 'Home') next = 0;
            else if (event.key === 'End') next = tabs.length - 1;
            else if (event.key !== ' ' && event.key !== 'Enter') return;
            event.preventDefault(); selectTab(tabs[next], true);
        });
    });
    form.addEventListener('invalid', function (event) {
        var panel = event.target.closest('[role="tabpanel"]');
        if (panel) selectTab(tabs.find(function (tab) { return tab.getAttribute('aria-controls') === panel.id; }), false);
    }, true);
    function revealHash() {
        var id;
        try { id = decodeURIComponent(window.location.hash.slice(1)); } catch (error) { return; }
        var target = document.getElementById(id);
        if (!target || !root.contains(target)) return;
        for (var parent = target; parent && parent !== root; parent = parent.parentElement) if (parent.tagName === 'DETAILS') parent.open = true;
        if (target.getAttribute('role') === 'tabpanel') {
            var tab = tabs.find(function (item) { return item.getAttribute('aria-controls') === target.id; });
            if (tab) selectTab(tab, false);
        }
    }
    window.addEventListener('hashchange', revealHash); revealHash();
    var nativeField = document.getElementById('native_probe_groups');
    var nativeChoices = Array.from(root.querySelectorAll('[data-native-group]'));
    function nativeToChoices() {
        var selected = nativeField.value.trim().split(/\s+/);
        nativeChoices.forEach(function (input) { input.checked = selected.indexOf(input.dataset.nativeGroup) !== -1; });
    }
    function choicesToNative() { nativeField.value = nativeChoices.filter(function (input) { return input.checked; }).map(function (input) { return input.dataset.nativeGroup; }).join('\n'); }
    nativeChoices.forEach(function (input) { input.addEventListener('change', choicesToNative); });
    form.addEventListener('submit', choicesToNative);
    document.getElementById('amsfb-defaults').addEventListener('click', function () {
        form.querySelectorAll('[data-default]').forEach(function (input) { input.value = input.dataset.default; });
        nativeToChoices();
        document.getElementById('policy-feedback').textContent = 'Padrões preenchidos em todas as abas, ainda não salvos. Isso inclui desativar a análise automática até novo ajuste. Confira antes de salvar.';
    });

    var maintenance = document.getElementById('amsfb-maintenance');
    var kind = document.getElementById('maintenance-kind');
    var scope = document.getElementById('maintenance-scope');
    var preview = document.getElementById('maintenance-preview');
    var queue = document.getElementById('maintenance-queue');
    var confirmation = document.getElementById('maintenance-confirm');
    var output = document.getElementById('maintenance-output');
    var status = document.getElementById('maintenance-status');
    var summary = document.getElementById('maintenance-preview-summary');
    var generation = 0, nonce = '', expiresAt = 0, busy = false, controller = null, expiryTimer = null;
    var csrf = root.dataset.csrf;
    function archiveSelected() { return kind.value === 'archive' || kind.value === 'both'; }
    function unbanSelected() { return kind.value === 'unban' || kind.value === 'both'; }
    function data() {
        return {kind: kind.value, scope: unbanSelected() ? scope.value : 'ai',
            jails: unbanSelected() && scope.value === 'selected' ? document.getElementById('maintenance-jails').value : '',
            cutoff: archiveSelected() ? document.getElementById('maintenance-cutoff').value : '',
            clear_logs: archiveSelected() && document.getElementById('maintenance-logs').checked ? '1' : '0',
            clear_suggestions: archiveSelected() && document.getElementById('maintenance-suggestions').checked ? '1' : '0',
            clear_observations: archiveSelected() && document.getElementById('maintenance-observations').checked ? '1' : '0',
            monitor: kind.value === 'monitor' || document.getElementById('maintenance-monitor').checked ? '1' : '0'};
    }
    function gate() { queue.disabled = busy || !nonce || Date.now() >= expiresAt || confirmation.value !== 'EXECUTAR MANUTENCAO'; }
    function controls() {
        maintenance.querySelector('[data-unban-controls]').hidden = !unbanSelected();
        maintenance.querySelector('[data-selected-jails]').hidden = !unbanSelected() || scope.value !== 'selected';
        maintenance.querySelector('[data-archive-controls]').hidden = !archiveSelected();
        maintenance.querySelector('[data-optional-monitor]').hidden = kind.value === 'monitor';
    }
    function invalidate() {
        generation += 1; nonce = ''; expiresAt = 0; clearTimeout(expiryTimer);
        confirmation.value = '';
        if (controller) controller.abort();
        summary.hidden = true; gate(); controls();
        status.textContent = 'Parâmetros alterados. Gere uma nova prévia antes de confirmar.';
    }
    maintenance.querySelectorAll('select,input').forEach(function (input) {
        if (input === confirmation) return;
        input.addEventListener('change', invalidate);
        input.addEventListener('input', invalidate);
    });
    confirmation.addEventListener('input', gate);
    function post(op, payload, signal) {
        var body = Object.assign({}, payload, {csrf_token: csrf});
        return fetch(root.dataset.endpoint + '&do=' + encodeURIComponent(op), {
            method: 'POST', credentials: 'same-origin', signal: signal,
            headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'},
            body: new URLSearchParams(body)
        }).then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        }).then(function (result) {
            if (result.csrf_token) csrf = result.csrf_token;
            return result;
        });
    }
    function errorMessage(error) {
        return error.name === 'AbortError' ? 'Consulta cancelada ou prazo de comunicação esgotado.' : 'Falha de comunicação. Confira o histórico antes de repetir uma confirmação.';
    }
    function show(result) { output.textContent = JSON.stringify(result, null, 2); }
    preview.addEventListener('click', function () {
        invalidate(); var version = generation, frozen = data(), signature = JSON.stringify(frozen), requestedAt = Date.now();
        controller = new AbortController(); var requestController = controller;
        var timer = setTimeout(function () { requestController.abort(); }, 45000);
        status.textContent = 'Consultando alvos para a prévia…';
        post('preview', frozen, requestController.signal).then(function (result) {
            if (version !== generation || signature !== JSON.stringify(data())) return;
            show(result);
            if (!result.success || !result.nonce) { status.textContent = result.error || 'Prévia não confirmada.'; return; }
            // Consent belongs to the displayed targets, never a previous/in-flight preview.
            confirmation.value = '';
            // Conservative deadline: transport/processing delay never extends server TTL.
            nonce = result.nonce; expiresAt = requestedAt + Math.min(300, Math.max(0, Number(result.expires_in) || 0)) * 1000;
            if (expiresAt <= Date.now()) { nonce = ''; gate(); status.textContent = 'Prévia vencida. Gere uma nova prévia.'; return; }
            var operations = {monitor:'Somente acompanhar', archive:'Arquivar e limpar histórico', unban:'Desbloquear alvos', both:'Arquivar/limpar e desbloquear'};
            summary.textContent = operations[frozen.kind] + '. Escopo dos desbloqueios: ' + (unbanSelected() ? ({ai:'jails da IA',all:'todas as jails',selected:frozen.jails}[frozen.scope]) : 'não se aplica') +
                '. Tickets congelados: ' + Number(result.bans || 0) + '. Registros de histórico selecionados: ' + Object.entries(result.records || {}).map(function (entry) { return entry[0] + ' ' + Number(entry[1]); }).join(', ') +
                '. Corte: ' + (result.cutoff || 'não informado') + '. Acompanhamento: ' + Number(result.monitor_hours || 0) + ' horas. ' + (result.notice || '');
            summary.hidden = false;
            status.textContent = 'Prévia válida por até cinco minutos. Confira o escopo congelado e digite a frase para habilitar a confirmação.';
            gate(); expiryTimer = setTimeout(function () { nonce = ''; gate(); status.textContent = 'Prévia vencida. Gere uma nova prévia.'; }, Math.max(0, expiresAt - Date.now()));
        }).catch(function (error) { if (version === generation) status.textContent = errorMessage(error); })
            .finally(function () { clearTimeout(timer); if (controller === requestController) controller = null; });
    });
    function mutate(op, payload, button) {
        if (busy) return;
        busy = true; button.disabled = true; preview.disabled = true; gate();
        var inputs = Array.from(maintenance.querySelectorAll('select,input'));
        inputs.forEach(function (input) { input.disabled = true; });
        var requestController = new AbortController();
        var timer = setTimeout(function () { requestController.abort(); }, 45000);
        status.textContent = 'Enviando solicitação explícita…';
        post(op, payload, requestController.signal).then(function (result) {
            show(result);
            status.textContent = result.success ? (result.job ? 'Trabalho ' + result.job + ' — ' + result.status + '. A execução depende do cron; consulte o Histórico.' : (result.notice || 'Solicitação registrada; recarregue para conferir.')) : (result.error || 'Solicitação recusada.');
            if (result.success && op === 'queue') { nonce = ''; expiresAt = 0; clearTimeout(expiryTimer); }
            if (!result.success) button.disabled = false;
        }).catch(function (error) { status.textContent = errorMessage(error) + ' Resultado não confirmado; consulte o Histórico antes de repetir.'; })
            .finally(function () { clearTimeout(timer); busy = false; preview.disabled = false; inputs.forEach(function (input) { input.disabled = false; }); gate(); });
    }
    queue.addEventListener('click', function () {
        gate(); if (queue.disabled) return;
        mutate('queue', {nonce: nonce, confirmation: confirmation.value}, queue);
    });
    root.querySelectorAll('.maintenance-retry').forEach(function (button) {
        button.addEventListener('click', function () {
            if (confirmation.value !== 'EXECUTAR MANUTENCAO') { status.textContent = 'Digite a frase de confirmação antes de retomar.'; confirmation.focus(); return; }
            mutate('retry', {job: button.dataset.job, confirmation: confirmation.value}, button);
        });
    });
    root.querySelectorAll('.queue-requeue:not([disabled])').forEach(function (button) {
        button.addEventListener('click', function () { mutate('requeue', {task: button.dataset.task}, button); });
    });
    controls(); gate();
})();
