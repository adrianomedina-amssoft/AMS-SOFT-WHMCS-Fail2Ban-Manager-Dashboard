<?php
/**
 * Reports template
 * Available: $rows, $total, $pages, $page, $filters, $jails, $actions
 */
?>

<div class="amsfb-page-header">
    <h3>&#128202; Relatórios</h3>
    <a href="<?= $e($modulelink . '&action=reports&do=export_csv'
        . '&date_from=' . urlencode($filters['date_from'])
        . '&date_to='   . urlencode($filters['date_to'])
        . '&ip='        . urlencode($filters['ip'])
        . '&jail='      . urlencode($filters['jail'])
        . '&action_filter=' . urlencode($filters['action'])
    ) ?>"
       class="btn btn-sm btn-success">
        &#11015; Export CSV
    </a>
</div>

<!-- Filters -->
<form method="get" action="<?= $e(strtok($modulelink, '?')) ?>" class="amsfb-filter-form form-inline">
    <input type="hidden" name="module"  value="amssoft_fail2ban">
    <input type="hidden" name="action"  value="reports">

    <div class="form-group">
        <label>De&nbsp;</label>
        <input type="date" name="date_from" class="form-control form-control-sm"
               value="<?= $e($filters['date_from']) ?>">
    </div>
    <div class="form-group">
        <label>&nbsp;Até&nbsp;</label>
        <input type="date" name="date_to" class="form-control form-control-sm"
               value="<?= $e($filters['date_to']) ?>">
    </div>
    <div class="form-group">
        <input type="text" name="ip" class="form-control form-control-sm"
               placeholder="IP" value="<?= $e($filters['ip']) ?>" style="width:140px;">
    </div>
    <div class="form-group">
        <select name="jail" class="form-control form-control-sm">
            <option value="">Todos jails</option>
            <?php foreach ($jails as $j): ?>
            <option value="<?= $e($j) ?>" <?= $filters['jail'] === $j ? 'selected' : '' ?>>
                <?= $e($j) ?>
            </option>
            <?php endforeach; ?>
        </select>
    </div>
    <div class="form-group">
        <select name="action_filter" class="form-control form-control-sm">
            <option value="">Todas ações</option>
            <?php foreach ($actions as $a): ?>
            <option value="<?= $e($a) ?>" <?= $filters['action'] === $a ? 'selected' : '' ?>>
                <?= $e($a) ?>
            </option>
            <?php endforeach; ?>
        </select>
    </div>
    <button type="submit" class="btn btn-sm btn-primary">Filtrar</button>
    <a href="<?= $e($modulelink . '&action=reports') ?>" class="btn btn-sm btn-default">Limpar</a>
</form>

<p class="text-muted" style="margin-top:8px;">Total: <strong><?= (int)$total ?></strong> registro(s)</p>

<?php if (empty($rows)): ?>
<div class="alert alert-info">Nenhum registro encontrado com os filtros aplicados.</div>
<?php else: ?>

<div class="table-responsive">
    <table class="table table-striped table-hover amsfb-table amsfb-table-sm">
        <thead>
            <tr>
                <th>Data/Hora</th>
                <th>IP</th>
                <th>Jail</th>
                <th>Ação</th>
                <th>Motivo</th>
                <th>Admin</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $row): ?>
            <tr>
                <td><?= $e(\AMS\Fail2Ban\Helper::fmtDate($row['timestamp'])) ?></td>
                <td><code><?= $e($row['ip']) ?></code></td>
                <td><?= $e($row['jail']) ?></td>
                <td>
                    <?php
                    $actionClass = [
                        'ban'          => 'label-danger',
                        'manual_ban'   => 'label-warning',
                        'unban'        => 'label-success',
                        'manual_unban' => 'label-info',
                    ][$row['action']] ?? 'label-default';
                    ?>
                    <span class="label <?= $e($actionClass) ?>"><?= $e($row['action']) ?></span>
                </td>
                <td><?= $e($row['reason'] ?? '-') ?></td>
                <td><?= $row['admin_id'] ? $e($row['admin_id']) : '<span class="text-muted">auto</span>' ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Pagination -->
<?php if ($pages > 1): ?>
<nav aria-label="Paginação">
    <ul class="pagination pagination-sm">
        <?php if ($page > 1): ?>
        <li>
            <a href="<?= $e($modulelink . '&action=reports&page=' . ($page - 1)
                . '&date_from=' . urlencode($filters['date_from'])
                . '&date_to='   . urlencode($filters['date_to'])
                . '&ip='        . urlencode($filters['ip'])
                . '&jail='      . urlencode($filters['jail'])
                . '&action_filter=' . urlencode($filters['action'])
            ) ?>">&laquo;</a>
        </li>
        <?php endif; ?>

        <?php
        $start = max(1, $page - 3);
        $end   = min($pages, $page + 3);
        for ($p = $start; $p <= $end; $p++):
        ?>
        <li class="<?= $p === $page ? 'active' : '' ?>">
            <a href="<?= $e($modulelink . '&action=reports&page=' . $p
                . '&date_from=' . urlencode($filters['date_from'])
                . '&date_to='   . urlencode($filters['date_to'])
                . '&ip='        . urlencode($filters['ip'])
                . '&jail='      . urlencode($filters['jail'])
                . '&action_filter=' . urlencode($filters['action'])
            ) ?>"><?= $p ?></a>
        </li>
        <?php endfor; ?>

        <?php if ($page < $pages): ?>
        <li>
            <a href="<?= $e($modulelink . '&action=reports&page=' . ($page + 1)
                . '&date_from=' . urlencode($filters['date_from'])
                . '&date_to='   . urlencode($filters['date_to'])
                . '&ip='        . urlencode($filters['ip'])
                . '&jail='      . urlencode($filters['jail'])
                . '&action_filter=' . urlencode($filters['action'])
            ) ?>">&raquo;</a>
        </li>
        <?php endif; ?>
    </ul>
</nav>
<?php endif; ?>

<?php endif; ?>
