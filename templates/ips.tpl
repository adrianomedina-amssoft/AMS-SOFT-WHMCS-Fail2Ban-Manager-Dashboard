<?php
/**
 * IPs Banidos template
 * Available: $fail2ban_online, $error, $banned_ips (array), $jails (array)
 */
?>

<div class="amsfb-page-header">
    <h3>&#128683; IPs Banidos</h3>
    <button class="btn btn-sm btn-danger" data-toggle="modal" data-target="#modalBanIP">
        + Banir IP
    </button>
</div>

<!-- Filtros -->
<form method="get" action="<?= $e(strtok($modulelink, '?')) ?>" class="amsfb-filter-form form-inline" style="margin-bottom:12px;">
    <input type="hidden" name="module" value="amssoft_fail2ban">
    <input type="hidden" name="action" value="ips">

    <div class="form-group">
        <input type="text" name="ip" class="form-control form-control-sm"
               placeholder="Filtrar por IP" value="<?= $e($filters['ip']) ?>" style="width:160px;">
    </div>
    <div class="form-group">
        <select name="jail" class="form-control form-control-sm">
            <option value="">Todos os jails</option>
            <?php foreach ($jails as $j): ?>
            <option value="<?= $e($j) ?>" <?= $filters['jail'] === $j ? 'selected' : '' ?>>
                <?= $e($j) ?>
            </option>
            <?php endforeach; ?>
        </select>
    </div>
    <button type="submit" class="btn btn-sm btn-primary">Filtrar</button>
    <a href="<?= $e($modulelink . '&action=ips') ?>" class="btn btn-sm btn-default">Limpar</a>
</form>

<?php if ($error): ?>
<div class="alert alert-warning"><?= $e($error) ?></div>
<?php endif; ?>

<?php if (!$fail2ban_online): ?>
<div class="alert alert-danger">fail2ban está offline. Não é possível listar IPs banidos.</div>
<?php else: ?>

<?php if ($total_ips === 0): ?>
<div class="alert alert-success">Nenhum IP banido no momento.</div>
<?php else: ?>

<p class="text-muted" style="margin-bottom:8px;">
    <?= (int)$total_ips ?> IP(s) <?= ($filters['ip'] || $filters['jail']) ? 'encontrado(s)' : 'banido(s)' ?> &mdash; exibindo página <?= (int)$page ?> de <?= (int)$pages ?>
</p>

<div class="table-responsive">
    <table class="table table-striped table-hover amsfb-table" id="tableIPs">
        <thead>
            <tr>
                <th>IP</th>
                <th>Jail</th>
                <th>Banido em</th>
                <th>Motivo</th>
                <th style="width:100px;">Ações</th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($banned_ips as $row): ?>
            <tr>
                <td><code><?= $e($row['ip']) ?></code></td>
                <td><?= $e($row['jail']) ?></td>
                <td><?= $e(\AMS\Fail2Ban\Helper::fmtDate($row['timestamp'] ?? '')) ?></td>
                <td><?= $e($row['reason'] ?? '-') ?></td>
                <td>
                    <form method="post" action="<?= $e($modulelink . '&action=ips') ?>"
                          class="amsfb-inline-form"
                          onsubmit="return confirm('Desbanir <?= $e(addslashes($row['ip'])) ?> de <?= $e(addslashes($row['jail'])) ?>?')">
                        <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
                        <input type="hidden" name="do"   value="unban">
                        <input type="hidden" name="ip"   value="<?= $e($row['ip']) ?>">
                        <input type="hidden" name="jail" value="<?= $e($row['jail']) ?>">
                        <button type="submit" class="btn btn-xs btn-warning">Desbanir</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Paginação de IPs banidos -->
<?php if ($pages > 1): ?>
<div class="amsfb-pagination-wrap">
    <nav aria-label="Paginação IPs">
        <ul class="pagination pagination-sm">
            <?php
            $ipFilterQs = '&ip=' . urlencode($filters['ip']) . '&jail=' . urlencode($filters['jail']);
            ?>
            <?php if ($page > 1): ?>
            <li>
                <a href="<?= $e($modulelink . '&action=ips&page=' . ($page - 1) . $ipFilterQs) ?>">&laquo;</a>
            </li>
            <?php endif; ?>

            <?php
            $ipStart = max(1, $page - 3);
            $ipEnd   = min($pages, $page + 3);
            for ($p = $ipStart; $p <= $ipEnd; $p++):
            ?>
            <li class="<?= $p === $page ? 'active' : '' ?>">
                <a href="<?= $e($modulelink . '&action=ips&page=' . $p . $ipFilterQs) ?>"><?= $p ?></a>
            </li>
            <?php endfor; ?>

            <?php if ($page < $pages): ?>
            <li>
                <a href="<?= $e($modulelink . '&action=ips&page=' . ($page + 1) . $ipFilterQs) ?>">&raquo;</a>
            </li>
            <?php endif; ?>
        </ul>
    </nav>
</div>
<?php endif; ?>

<?php endif; ?>
<?php endif; ?>

<!-- Modal: Banir IP -->
<div class="modal fade" id="modalBanIP" tabindex="-1" role="dialog" aria-labelledby="modalBanIPLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="<?= $e($modulelink . '&action=ips') ?>">
                <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
                <input type="hidden" name="do" value="ban">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Fechar">
                        <span aria-hidden="true">&times;</span>
                    </button>
                    <h4 class="modal-title" id="modalBanIPLabel">Banir IP manualmente</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>IP</label>
                        <input type="text" name="ip" class="form-control"
                               placeholder="192.168.1.1" required
                               pattern="^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$|^([0-9a-fA-F:]+)$"
                               value="<?= $e($ban_ip ?? '') ?>">
                    </div>
                    <div class="form-group">
                        <label>Jail</label>
                        <select name="jail" class="form-control" required>
                            <option value="">— selecione —</option>
                            <?php foreach ($jails as $j): ?>
                            <option value="<?= $e($j) ?>"><?= $e($j) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-danger">Banir IP</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
(function () {
    // Auto-abrir modal "Banir IP" com IP pré-preenchido
    // (acionado quando o admin vem da tela de Sugestões IA com jail inativável)
    <?php if (!empty($open_ban_modal) && !empty($ban_ip)): ?>
    (function () {
        function openBanModal() {
            if (typeof $ !== 'undefined') {
                $('#modalBanIP').modal('show');
            } else if (typeof bootstrap !== 'undefined') {
                var el = document.getElementById('modalBanIP');
                if (el) new bootstrap.Modal(el).show();
            }
        }
        if (typeof $ !== 'undefined') {
            $(document).ready(openBanModal);
        } else {
            document.addEventListener('DOMContentLoaded', openBanModal);
        }
    })();
    <?php endif; ?>

    // filtro client-side removido (paginação server-side)
})();
</script>
