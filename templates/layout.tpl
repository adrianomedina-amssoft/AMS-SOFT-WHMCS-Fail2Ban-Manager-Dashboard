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
    </ul>

    <!-- Flash message -->
    <?php if (!empty($flash)): ?>
    <div class="alert alert-<?= $e($flash['type']) ?> alert-dismissible amsfb-flash" role="alert">
        <button type="button" class="close" data-dismiss="alert" aria-label="Fechar">
            <span aria-hidden="true">&times;</span>
        </button>
        <?= $e($flash['message']) ?>
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
window.AMSFB.moduleLink  = <?= json_encode($modulelink) ?>;
window.AMSFB.csrfToken   = <?= json_encode($csrf_token) ?>;
window.AMSFB.currentAction = <?= json_encode($current_action) ?>;
</script>
