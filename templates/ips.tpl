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

<?php if ($error): ?>
<div class="alert alert-warning"><?= $e($error) ?></div>
<?php endif; ?>

<?php if (!$fail2ban_online): ?>
<div class="alert alert-danger">fail2ban está offline. Não é possível listar IPs banidos.</div>
<?php else: ?>

<!-- Search -->
<div class="form-group amsfb-search-wrap">
    <input type="text" id="ipSearch" class="form-control" placeholder="Filtrar por IP..." style="max-width:260px;">
</div>

<?php if (empty($banned_ips)): ?>
<div class="alert alert-success">Nenhum IP banido no momento.</div>
<?php else: ?>

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
            <tr class="amsfb-ip-row">
                <td class="amsfb-ip-cell"><code><?= $e($row['ip']) ?></code></td>
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

    var input = document.getElementById('ipSearch');
    if (!input) return;
    input.addEventListener('keyup', function () {
        var q    = this.value.toLowerCase();
        var rows = document.querySelectorAll('#tableIPs .amsfb-ip-row');
        rows.forEach(function (row) {
            var ip = row.querySelector('.amsfb-ip-cell');
            row.style.display = (!ip || ip.textContent.toLowerCase().indexOf(q) !== -1) ? '' : 'none';
        });
    });
})();
</script>
