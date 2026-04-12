<?php
/**
 * AMS Fail2Ban Manager — layout wrapper.
 * Variables injected by Router::render():
 *   $e             — escaping closure: $e($val)
 *   $modulelink    — base WHMCS module URL
 *   $current_action— active route
 *   $flash         — ['type'=>..., 'message'=>...] or null
 *   $asset_base    — URL base for CSS/JS assets
 *   $content       — rendered inner template HTML
 */
?>
<link rel="stylesheet" href="<?= $e($asset_base . 'css/amssoft_fail2ban.css') ?>">

<div id="amssoft-fail2ban">

    <!-- Top navigation pills -->
    <ul class="nav nav-pills amsfb-nav" role="tablist">
        <?php
        $navItems = [
            'dashboard'  => ['icon' => '&#9776;',   'label' => 'Dashboard'],
            'ips'        => ['icon' => '&#128683;',  'label' => 'IPs Banidos'],
            'jails'      => ['icon' => '&#128274;',  'label' => 'Jails'],
            'logpaths'   => ['icon' => '&#128196;',  'label' => 'Log Paths'],
            'reports'    => ['icon' => '&#128202;',  'label' => 'Relatórios'],
            'logviewer'  => ['icon' => '&#128220;',  'label' => 'Log Viewer'],
            'ai'         => ['icon' => '&#129302;',  'label' => 'IA'],
        ];
        $activeNav = match(true) {
            in_array($current_action, ['jail_edit'], true) => 'jails',
            $current_action === 'ai_settings'              => 'ai',
            default                                        => $current_action,
        };
        foreach ($navItems as $act => $item):
            $isActive = ($activeNav === $act);
        ?>
        <li role="presentation" class="<?= $isActive ? 'active' : '' ?>">
            <a href="<?= $e($modulelink . '&action=' . $act) ?>">
                <?= $item['icon'] ?> <?= $e($item['label']) ?>
            </a>
        </li>
        <?php endforeach; ?>
        <li role="presentation" style="margin-left:auto; display:flex; align-items:center; padding: 4px 0;">
            <button type="button" class="amsfb-support-btn" data-toggle="modal" data-target="#amsfb-support-modal">
                &#9749; Apoie
            </button>
        </li>
    </ul>

    <!-- ── Modal: Apoie o Projeto ────────────────────────────────────────── -->
    <div class="modal fade amsfb-support-modal" id="amsfb-support-modal" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-sm" role="document" style="max-width:480px;">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">&#9749; Apoie o Projeto</h4>
                </div>
                <div class="modal-body">
                    <div class="amsfb-support-hero">
                        <span class="amsfb-support-icon">&#128591;</span>
                        <p>
                            O <strong>AMS SOFT Fail2Ban Manager</strong> é gratuito e de código aberto.<br>
                            Se ele ajudou a proteger o seu servidor, considere uma doação —
                            qualquer valor faz diferença para manter o projeto vivo e evoluindo.
                        </p>
                    </div>

                    <div class="amsfb-donate-btns">
                        <a href="https://www.mercadopago.com.br/subscriptions/checkout?preapproval_plan_id=95add4219a6b47f286b1405a51a39b7b"
                           target="_blank" rel="noopener"
                           class="amsfb-donate-btn amsfb-donate-btn-mp">
                            &#128179; Mercado Pago
                        </a>
                        <a href="https://www.paypal.com/ncp/payment/UZQBBQ4BQ89UQ"
                           target="_blank" rel="noopener"
                           class="amsfb-donate-btn amsfb-donate-btn-pp">
                            &#128179; PayPal
                        </a>
                    </div>

                    <div class="amsfb-support-dismiss" id="amsfb-support-dismiss-wrap">
                        <label>
                            <input type="checkbox" id="amsfb-support-no-popup">
                            &nbsp;Não exibir este popup novamente
                        </label>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- System requirement warnings -->
    <?php if (!empty($system_warnings)): ?>
        <?php foreach ($system_warnings as $warn): ?>
        <div class="alert alert-<?= $e($warn['level']) ?> alert-dismissible" role="alert">
            <button type="button" class="close" data-dismiss="alert" aria-label="Fechar">
                <span aria-hidden="true">&times;</span>
            </button>
            <strong>&#9888; Requisito do sistema:</strong> <?= $warn['message'] ?>
            <?php if (!empty($warn['fix'])): ?>
            <br><small>Comando para corrigir: <code><?= $warn['fix'] ?></code></small>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <!-- Flash message -->
    <?php if (!empty($flash)): ?>
    <div class="alert alert-<?= $e($flash['type']) ?> alert-dismissible amsfb-flash" role="alert">
        <button type="button" class="close" data-dismiss="alert" aria-label="Fechar">
            <span aria-hidden="true">&times;</span>
        </button>
        <?= $e($flash['message']) ?>
        <?php if (!empty($flash['detail'])): ?>
        <pre style="margin-top:6px;margin-bottom:0;font-size:11px;white-space:pre-wrap;word-break:break-all;background:rgba(0,0,0,.05);padding:6px;border-radius:3px;"><?= $e($flash['detail']) ?></pre>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- Main content -->
    <div class="amsfb-content">
        <?= $content ?>
    </div>

</div><!-- #amssoft-fail2ban -->

<script src="<?= $e($asset_base . 'js/chart.min.js') ?>"></script>
<script src="<?= $e($asset_base . 'js/amssoft_fail2ban.js') ?>"></script>
<script>
window.AMSFB = window.AMSFB || {};
window.AMSFB.moduleLink    = <?= json_encode($modulelink) ?>;
window.AMSFB.csrfToken     = <?= json_encode($csrf_token) ?>;
window.AMSFB.currentAction = <?= json_encode($current_action) ?>;
</script>
<script>
(function () {
    var DISMISS_KEY = 'amsfb_support_dismissed';

    // Checkbox "não exibir novamente": salva no localStorage ao marcar
    var chk = document.getElementById('amsfb-support-no-popup');
    if (chk) {
        chk.addEventListener('change', function () {
            if (this.checked) {
                try { localStorage.setItem(DISMISS_KEY, '1'); } catch (e) {}
            } else {
                try { localStorage.removeItem(DISMISS_KEY); } catch (e) {}
            }
        });
    }

    // Popup automático: só no dashboard, só se não foi dispensado
    var isDashboard = (window.AMSFB.currentAction === 'dashboard');
    var isDismissed = false;
    try { isDismissed = localStorage.getItem(DISMISS_KEY) === '1'; } catch (e) {}

    if (isDashboard && !isDismissed) {
        function openSupportModal() {
            if (typeof $ !== 'undefined') {
                $('#amsfb-support-modal').modal('show');
            } else if (typeof bootstrap !== 'undefined') {
                var el = document.getElementById('amsfb-support-modal');
                if (el) new bootstrap.Modal(el).show();
            }
        }
        // Aguarda um momento para o admin ver o dashboard antes do popup
        if (typeof $ !== 'undefined') {
            $(document).ready(function () { setTimeout(openSupportModal, 1200); });
        } else {
            document.addEventListener('DOMContentLoaded', function () {
                setTimeout(openSupportModal, 1200);
            });
        }
    }
})();
</script>
