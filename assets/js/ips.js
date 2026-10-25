(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', function () {
        var root = document.getElementById('amsfb-ips-view');
        if (!root) return;
        var busy = false;
        function notice(message, warning) {
            var box = document.getElementById('amsfb-ips-notice');
            box.textContent = message;
            box.className = 'alert alert-' + (warning ? 'warning' : 'success');
            box.hidden = false;
            box.focus();
        }
        function token() { return (window.AMSFB && window.AMSFB.csrfToken) || root.dataset.csrf || ''; }
        root.querySelectorAll('.amsfb-ips-unban').forEach(function (button) {
            button.addEventListener('click', function () {
                if (busy || button.disabled) return;
                var ip = button.dataset.ip, jail = button.dataset.jail;
                if (!confirm('Remover o ticket exibido de ' + ip + ' somente da jail ' + jail + '? Outras jails permanecem independentes; não cria whitelist.')) return;
                busy = true; button.disabled = true;
                function send(retried) {
                    var body = new URLSearchParams({csrf_token: token(), ip: ip, jail: jail, preview: button.dataset.preview});
                    return fetch(root.dataset.moduleLink + '&action=ips&do=unban', {
                        method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'}, body: body.toString()
                    }).then(function (response) {
                        if (!response.ok) throw new Error('HTTP ' + response.status);
                        return response.json();
                    }).then(function (data) {
                        if (!data || typeof data.success !== 'boolean') throw new Error('Resposta inválida');
                        if (typeof data.csrf_token === 'string') {
                            root.dataset.csrf = data.csrf_token;
                            if (window.AMSFB) window.AMSFB.csrfToken = data.csrf_token;
                        }
                        if (!data.success && typeof data.error === 'string' && /CSRF/i.test(data.error) && !retried) return send(true);
                        if (data.success) {
                            notice(data.message || 'Estado confirmado. Atualizando a lista.', !!data.warning);
                            // A fresh GET recomputes totals, pagination and other jail tickets.
                            window.location.reload();
                        } else {
                            busy = false; button.disabled = false;
                            notice(data.error || 'Operação não confirmada. Atualize antes de repetir.', true);
                        }
                    });
                }
                send(false).catch(function () {
                    busy = false; button.disabled = false;
                    notice('Não foi possível confirmar o resultado. Atualize a lista antes de repetir; a operação pode ter sido aplicada.', true);
                });
            });
        });
        var form = document.getElementById('amsfb-ips-ban-form');
        if (form) form.addEventListener('submit', function (event) {
            if (busy || !confirm('Confirmar ban manual deste IP na jail selecionada?')) { event.preventDefault(); return; }
            busy = true;
        });
        if (root.dataset.openModal === '1') {
            if (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal) window.jQuery('#modalBanIP').modal('show');
            else if (window.bootstrap && window.bootstrap.Modal) new window.bootstrap.Modal(document.getElementById('modalBanIP')).show();
        }
    });
})();
