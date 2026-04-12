/**
 * AMS Fail2Ban Manager — admin JavaScript
 * Requires: jQuery (available in WHMCS admin), Chart.js (assets/js/chart.min.js)
 */
(function () {
    'use strict';

    /* ------------------------------------------------------------------ */
    /* Auto-dismiss flash messages                                         */
    /* ------------------------------------------------------------------ */
    var flash = document.querySelector('.amsfb-flash');
    if (flash) {
        setTimeout(function () {
            flash.style.transition = 'opacity .6s ease';
            flash.style.opacity    = '0';
            setTimeout(function () {
                if (flash.parentNode) {
                    flash.parentNode.removeChild(flash);
                }
            }, 700);
        }, 5000);
    }

    /* ------------------------------------------------------------------ */
    /* Highlight active row on hover (touch-friendly)                     */
    /* ------------------------------------------------------------------ */
    document.querySelectorAll('.amsfb-table tbody tr').forEach(function (row) {
        row.style.cursor = 'default';
    });

    /* ------------------------------------------------------------------ */
    /* Reports: disable Export button while submitting                    */
    /* ------------------------------------------------------------------ */
    var exportLink = document.querySelector('a[href*="do=export_csv"]');
    if (exportLink) {
        exportLink.addEventListener('click', function () {
            var btn = this;
            btn.classList.add('disabled');
            btn.textContent = '⏳ Gerando...';
            setTimeout(function () {
                btn.classList.remove('disabled');
                btn.textContent = '⬇ Export CSV';
            }, 4000);
        });
    }

    /* ------------------------------------------------------------------ */
    /* Confirm dialogs for destructive actions                            */
    /* ------------------------------------------------------------------ */
    document.querySelectorAll('[data-confirm]').forEach(function (el) {
        el.addEventListener('click', function (ev) {
            if (!confirm(this.dataset.confirm)) {
                ev.preventDefault();
                ev.stopImmediatePropagation();
            }
        });
    });

    /* ------------------------------------------------------------------ */
    /* IP search — handled inline in ips.tpl, but also bootstrap if       */
    /* the element exists on this page load                               */
    /* ------------------------------------------------------------------ */
    var ipSearch = document.getElementById('ipSearch');
    if (ipSearch && !ipSearch.__amsfbInit) {
        ipSearch.__amsfbInit = true;
        ipSearch.addEventListener('keyup', function () {
            var q    = this.value.toLowerCase();
            var rows = document.querySelectorAll('#tableIPs .amsfb-ip-row');
            rows.forEach(function (row) {
                var cell = row.querySelector('.amsfb-ip-cell');
                row.style.display = (!cell || cell.textContent.toLowerCase().indexOf(q) !== -1) ? '' : 'none';
            });
        });
    }

    /* ------------------------------------------------------------------ */
    /* Generic AJAX helper used by inline Validate buttons                */
    /* ------------------------------------------------------------------ */
    window.AMSFB = window.AMSFB || {};

    /**
     * amsfbPost(path, params) → Promise<Object>
     * Sends a POST request with CSRF token and returns parsed JSON.
     */
    window.AMSFB.post = function (path, params) {
        var body = 'csrf_token=' + encodeURIComponent(window.AMSFB.csrfToken || '');
        Object.keys(params || {}).forEach(function (k) {
            body += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
        });
        return fetch(path, {
            method:  'POST',
            headers: {
                'Content-Type':     'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
            },
            body: body,
        }).then(function (r) {
            if (!r.ok) {
                throw new Error('HTTP ' + r.status);
            }
            return r.json();
        }).then(function (data) {
            // [SEC-7] If the server rotated the CSRF token, keep the local copy in sync
            // so the next request uses the new token without a page reload.
            if (data && data.csrf_token) {
                window.AMSFB.csrfToken = data.csrf_token;
            }
            return data;
        });
    };

})();
