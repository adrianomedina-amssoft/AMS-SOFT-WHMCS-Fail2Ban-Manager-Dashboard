<?php
/**
 * Dashboard template
 * Available: $fail2ban_online, $error, $total_banned_now, $bans_24h,
 *            $active_jails, $last_ban, $jail_statuses,
 *            $series_labels (JSON), $series_counts (JSON),
 *            $top_ip_labels (JSON), $top_ip_counts (JSON)
 */
?>

<div class="amsfb-page-header">
    <h3>&#9776; Dashboard</h3>
    <span class="label <?= $fail2ban_online ? 'label-success' : 'label-danger' ?>">
        fail2ban <?= $fail2ban_online ? 'online' : 'offline' ?>
    </span>
</div>

<?php if ($error): ?>
<div class="alert alert-warning"><?= $e($error) ?></div>
<?php endif; ?>

<!-- KPI cards -->
<div class="row amsfb-kpi-row">
    <div class="col-sm-3">
        <div class="amsfb-kpi-card amsfb-kpi-red">
            <div class="amsfb-kpi-value"><?= (int)$total_banned_now ?></div>
            <div class="amsfb-kpi-label">Banidos agora</div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="amsfb-kpi-card amsfb-kpi-orange">
            <div class="amsfb-kpi-value"><?= (int)$bans_24h ?></div>
            <div class="amsfb-kpi-label">Bans 24h (DB)</div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="amsfb-kpi-card amsfb-kpi-blue">
            <div class="amsfb-kpi-value"><?= (int)$active_jails ?></div>
            <div class="amsfb-kpi-label">Jails ativos</div>
        </div>
    </div>
    <div class="col-sm-3">
        <div class="amsfb-kpi-card amsfb-kpi-green">
            <div class="amsfb-kpi-value amsfb-kpi-sm">
                <?= $last_ban ? $e($last_ban['ip']) : '-' ?>
            </div>
            <div class="amsfb-kpi-label">Último ban</div>
        </div>
    </div>
</div>

<!-- Charts row -->
<div class="row" style="margin-top:24px;">
    <div class="col-md-7">
        <div class="panel panel-default">
            <div class="panel-heading"><strong>Bans — últimos 7 dias</strong></div>
            <div class="panel-body">
                <canvas id="chartBansSeries" height="120"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-5">
        <div class="panel panel-default">
            <div class="panel-heading"><strong>Top 10 IPs</strong></div>
            <div class="panel-body">
                <canvas id="chartTopIps" height="200"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- Jail status table -->
<?php if (!empty($jail_statuses)): ?>
<div class="panel panel-default" style="margin-top:16px;">
    <div class="panel-heading"><strong>Status por Jail</strong></div>
    <div class="table-responsive">
        <table class="table table-striped table-hover amsfb-table">
            <thead>
                <tr>
                    <th>Jail</th>
                    <th>Banidos</th>
                    <th>Total Bans</th>
                    <th>Falhas Atuais</th>
                    <th>Total Falhas</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($jail_statuses as $jail => $s): ?>
                <tr>
                    <td>
                        <a href="<?= $e($modulelink . '&action=jail_edit&jail=' . urlencode($jail)) ?>">
                            <?= $e($jail) ?>
                        </a>
                    </td>
                    <td>
                        <span class="badge <?= $s['currently_banned'] > 0 ? 'badge-danger' : 'badge-default' ?>">
                            <?= (int)$s['currently_banned'] ?>
                        </span>
                    </td>
                    <td><?= (int)$s['total_banned'] ?></td>
                    <td><?= (int)$s['currently_failed'] ?></td>
                    <td><?= (int)$s['total_failed'] ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php elseif (!$fail2ban_online): ?>
<div class="alert alert-info">fail2ban está offline ou inacessível. Verifique sudo/fail2ban-client nas configurações do módulo.</div>
<?php endif; ?>

<script>
(function () {
    if (typeof Chart === 'undefined') return;

    // Line chart — bans series
    var ctxLine = document.getElementById('chartBansSeries');
    if (ctxLine) {
        new Chart(ctxLine, {
            type: 'line',
            data: {
                labels:   <?= $series_labels ?>,
                datasets: [{
                    label:           'Bans',
                    data:            <?= $series_counts ?>,
                    borderColor:     '#e74c3c',
                    backgroundColor: 'rgba(231,76,60,0.1)',
                    tension:         0.3,
                    fill:            true,
                    pointRadius:     4,
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
            }
        });
    }

    // Bar chart — top IPs
    var ctxBar = document.getElementById('chartTopIps');
    if (ctxBar) {
        new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels:   <?= $top_ip_labels ?>,
                datasets: [{
                    label:           'Bans',
                    data:            <?= $top_ip_counts ?>,
                    backgroundColor: '#3498db',
                }]
            },
            options: {
                indexAxis:  'y',
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
            }
        });
    }
})();
</script>
