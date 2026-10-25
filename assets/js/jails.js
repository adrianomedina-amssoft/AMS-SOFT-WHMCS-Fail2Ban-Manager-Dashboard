(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', function () {
        var root = document.getElementById('amsfb-jails-view');
        if (!root) return;
        var busy = false;
        function token() { return (window.AMSFB && window.AMSFB.csrfToken) || root.dataset.csrf || ''; }
        function notice(message) {
            var box = document.getElementById('amsfb-jails-notice');
            box.textContent = message; box.className = 'alert alert-warning'; box.hidden = false; box.focus();
        }
        root.querySelectorAll('.amsfb-jail-action').forEach(function (button) {
            button.addEventListener('click', function () {
                if (busy || button.disabled) return;
                var operation = button.dataset.do;
                var impact = operation === 'remove'
                    ? 'Remover SOMENTE a seção local pode revelar configuração herdada e reativar a jail. Não exclui filtros.'
                    : operation === 'disable' ? 'Desabilitar pode liberar os bloqueios desta jail.' : 'Habilitar passa a aplicar as regras e bloqueios desta jail.';
                if (!confirm(button.dataset.jail + ': ' + impact + ' Confirmar aplicação e reload?')) return;
                busy = true; button.disabled = true;
                function send(retried) {
                    var body = new URLSearchParams({csrf_token: token(), jail: button.dataset.jail, do: operation, preview: button.dataset.preview, confirm: '1'});
                    return fetch(root.dataset.moduleLink + '&action=jails&do=' + encodeURIComponent(operation), {
                        method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'}, body: body.toString()
                    }).then(function (response) {
                        if (!response.ok) throw new Error('HTTP');
                        return response.json();
                    }).then(function (data) {
                        if (!data || typeof data.success !== 'boolean') throw new Error('Invalid JSON');
                        if (typeof data.csrf_token === 'string') {
                            root.dataset.csrf = data.csrf_token;
                            if (window.AMSFB) window.AMSFB.csrfToken = data.csrf_token;
                        }
                        if (!data.success && typeof data.error === 'string' && /CSRF/i.test(data.error) && !retried) return send(true);
                        if (data.success) { window.location.reload(); return; }
                        notice(data.error || 'Resultado não confirmado. Atualize a página antes de agir novamente.');
                    });
                }
                send(false).catch(function () {
                    notice('Falha de comunicação. A operação pode ter sido aplicada. Atualize a página antes de repetir; nenhum reenvio automático foi feito.');
                });
            });
        });
        root.querySelectorAll('.amsfb-jail-form').forEach(function (form) {
            form.addEventListener('submit', function (event) {
                if (busy || !confirm('Confirmar os valores e aplicar a configuração? O reload pode afetar a proteção e os bloqueios da jail.')) { event.preventDefault(); return; }
                form.querySelector('input[name="csrf_token"]').value = token();
                busy = true;
            });
        });
    });
})();
