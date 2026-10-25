<?php
$native=$view['native'];$filters=$view['filters'];$complete=$native['complete'];
$url=$modulelink.'&action=ips';$qs='&ip='.urlencode($filters['ip']).'&jail='.urlencode($filters['jail']);
?>
<div id="amsfb-ips-view" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>" data-open-modal="<?= $view['open_modal']?'1':'0' ?>">
<div class="amsfb-page-header">
    <h3>&#128683; IPs e tickets de ban</h3>
    <button type="button" class="btn btn-sm btn-danger" data-toggle="modal" data-target="#modalBanIP" <?= !$complete||!$view['jails']?'disabled':'' ?>>+ Banir IP</button>
</div>
<p class="text-muted">Leitura iniciada em <?= $e(date('d/m/Y H:i:s',$native['at'])) ?> (<?= $e(date_default_timezone_get()) ?>).
    <a href="<?= $e($url.$qs.'&page='.$view['page']) ?>">Atualizar lista</a> · <a href="<?= $e($modulelink.'&action=protection') ?>">Conferir proteção efetiva</a>.
    Um ticket no daemon não comprova sozinho cobertura no firewall. Remover uma jail não remove bans nas demais nem cria whitelist.</p>
<div id="amsfb-ips-notice" role="alert" tabindex="-1" hidden></div>
<?php foreach(array_merge($native['error']?[$native['error']]:[],$view['errors']) as $message): ?>
<div class="alert alert-warning" role="alert"><?= $e($message) ?></div>
<?php endforeach; ?>
<form method="get" action="<?= $e(strtok($modulelink,'?')) ?>" class="amsfb-filter-form form-inline">
    <input type="hidden" name="module" value="amssoft_fail2ban"><input type="hidden" name="action" value="ips">
    <div class="form-group"><label for="amsfb-ip-filter">IP ou trecho</label>
        <input id="amsfb-ip-filter" type="text" name="ip" class="form-control" maxlength="50" placeholder="IPv4 ou IPv6, sem CIDR" value="<?= $e($filters['ip']) ?>"></div>
    <div class="form-group"><label for="amsfb-jail-filter">Jail carregada</label>
        <select id="amsfb-jail-filter" name="jail" class="form-control"><option value="">Todas</option>
        <?php if($filters['jail']!==''&&!in_array($filters['jail'],$view['jails'],true)): ?><option value="<?= $e($filters['jail']) ?>" selected><?= $e($filters['jail']) ?> (não carregada nesta leitura)</option><?php endif; ?>
        <?php foreach($view['jails'] as $jail): ?><option value="<?= $e($jail) ?>" <?= $filters['jail']===$jail?'selected':'' ?>><?= $e($jail) ?></option><?php endforeach; ?>
        </select></div>
    <button type="submit" class="btn btn-sm btn-primary">Filtrar</button>
    <a class="btn btn-sm btn-default" href="<?= $e($url) ?>">Limpar filtros</a>
</form>
<?php if($complete): ?>
<p data-counts="complete" style="margin-top:12px"><strong><?= (int)$view['unique'] ?> IP(s) único(s)</strong> em <strong><?= (int)$view['records'] ?> ticket(s)</strong>
    <?= $filters['ip']!==''||$filters['jail']!==''?'nos filtros selecionados':'na leitura completa' ?>.
    Total geral: <?= (int)$native['unique_ips'] ?> IP(s) / <?= (int)$native['tickets'] ?> ticket(s).</p>
<?php else: ?><p data-counts="partial"><strong>Totais gerais não medidos.</strong> Exibindo <?= (int)$view['records'] ?> registro(s) obtido(s) nos filtros; a lista pode estar incompleta.</p><?php endif; ?>
<?php if(!$view['rows']): ?>
<div class="alert alert-<?= $complete?'info':'warning' ?>">
    <?= !$complete?'Não foi possível confirmar a ausência de tickets.':(($filters['ip']!==''||$filters['jail']!=='')?'Nenhum ticket corresponde aos filtros; isso não significa ausência de outros bans.':'Nenhum ticket de ban nesta leitura do Fail2Ban.') ?>
</div>
<?php else: ?>
<div class="table-responsive"><table class="table table-striped table-hover amsfb-table" id="tableIPs">
    <caption>Uma linha por IP e jail. Ticket nativo e histórico do módulo são fontes distintas; horário/motivo histórico não identifica necessariamente o ban atual.</caption>
    <thead><tr><th scope="col">IP</th><th scope="col">Jail</th><th scope="col">Ticket nativo</th><th scope="col">Último ban no módulo nesta jail</th><th scope="col">Ação</th></tr></thead>
    <tbody><?php foreach($view['rows'] as $row): ?>
    <tr><th scope="row"><code><?= $e($row['ip']) ?></code>
        <?php if(!empty($view['geo'][$row['ip']])): ?><br><small><?= $e(\AMS\Fail2Ban\GeoIP::formatGeo($view['geo'][$row['ip']])) ?> (cache)</small><?php endif; ?></th>
        <td style="overflow-wrap:anywhere"><?= $e($row['jail']) ?></td>
        <td style="min-width:180px;overflow-wrap:anywhere"><?php if($row['ticket']): ?><?= $e($row['ticket']) ?><br><small class="text-muted">Início + duração = término, informado pelo daemon.</small><?php else: ?>Não confirmado; pode ter expirado ou mudado.<?php endif; ?></td>
        <td style="max-width:360px;overflow-wrap:anywhere"><?php if($row['history']): ?><?= $e($row['history']['timestamp']) ?><br><?= $e($row['history']['reason']??'Sem motivo registrado') ?><?php else: ?><?= $row['history_known']?'Sem registro do módulo para este IP/jail.':'Histórico não medido.' ?><?php endif; ?></td>
        <td><button type="button" class="btn btn-xs btn-warning amsfb-ips-unban" data-ip="<?= $e($row['ip']) ?>" data-jail="<?= $e($row['jail']) ?>" data-preview="<?= $e($row['preview']??'') ?>" <?= !$row['preview']?'disabled':'' ?>>Desbanir desta jail</button></td>
    </tr><?php endforeach; ?></tbody>
</table></div>
<?php endif; ?>
<p>Página <?= (int)$view['page'] ?> de <?= (int)$view['pages'] ?>. Até 10 tickets por página; ordenação por IP e jail.</p>
<?php if($view['pages']>1): ?><nav aria-label="Páginas de tickets"><ul class="pagination pagination-sm">
    <?php if($view['page']>1): ?><li><a aria-label="Página anterior" href="<?= $e($url.$qs.'&page='.($view['page']-1)) ?>">&laquo;</a></li><?php endif; ?>
    <?php for($p=max(1,$view['page']-3);$p<=min($view['pages'],$view['page']+3);$p++): ?><li class="<?= $p===$view['page']?'active':'' ?>"><a <?= $p===$view['page']?'aria-current="page"':'' ?> href="<?= $e($url.$qs.'&page='.$p) ?>"><?= $p ?></a></li><?php endfor; ?>
    <?php if($view['page']<$view['pages']): ?><li><a aria-label="Próxima página" href="<?= $e($url.$qs.'&page='.($view['page']+1)) ?>">&raquo;</a></li><?php endif; ?>
</ul></nav><?php endif; ?>

<div class="modal fade" id="modalBanIP" tabindex="-1" role="dialog" aria-labelledby="modalBanIPLabel">
<div class="modal-dialog" role="document"><div class="modal-content">
    <form id="amsfb-ips-ban-form" method="post" action="<?= $e($url) ?>">
        <input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>"><input type="hidden" name="do" value="ban">
        <div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Fechar">&times;</button><h4 class="modal-title" id="modalBanIPLabel">Ban manual em uma jail carregada</h4></div>
        <div class="modal-body">
            <p>A ação usa a duração e as portas da jail selecionada. Endereços protegidos e whitelist continuam sendo respeitados. Não cria nem ativa jails.</p>
            <div class="form-group"><label for="amsfb-ban-ip">IP completo</label><input id="amsfb-ban-ip" type="text" name="ip" class="form-control" required maxlength="45" placeholder="IPv4 ou IPv6, sem CIDR" value="<?= $e($view['ban_ip']) ?>"></div>
            <div class="form-group"><label for="amsfb-ban-jail">Jail carregada</label><select id="amsfb-ban-jail" name="jail" class="form-control" required><option value="">Selecione</option><?php foreach($view['jails'] as $jail): ?><option value="<?= $e($jail) ?>"><?= $e($jail) ?></option><?php endforeach; ?></select></div>
        </div>
        <div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Cancelar</button><button type="submit" class="btn btn-danger" <?= !$complete||!$view['jails']?'disabled':'' ?>>Confirmar ban</button></div>
    </form>
</div></div></div>
</div>
<script src="<?= $e($asset_base.'js/ips.js?v=2.2.41') ?>"></script>
