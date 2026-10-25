<?php
use AMS\Fail2Ban\JailAdmin;
$s=$view['selection'];$snapshot=$view['snapshot'];$ready=$snapshot!==null&&$view['names']!==null;
$url=static fn($p)=>$modulelink.'&action=jails&'.http_build_query(['q'=>$s['q'],'state'=>$s['state'],'page'=>$p]);
?>
<div id="amsfb-jails-view" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>">
<h3>Jails</h3>
<div id="amsfb-jails-notice" class="alert" role="status" tabindex="-1" hidden></div>
<?php foreach($view['errors'] as $message): ?><div class="alert alert-warning"><?= $e($message) ?></div><?php endforeach; ?>
<p data-jail-counts>Configuradas: <strong><?= $snapshot!==null?(int)$s['configured']:'não confirmado' ?></strong> · Habilitadas na configuração: <strong><?= $snapshot!==null?(int)$s['enabled']:'não confirmado' ?></strong> · Carregadas no daemon: <strong><?= $s['loaded']===null?'não confirmado':(int)$s['loaded'] ?></strong></p>
<p class="text-muted">Consulta em <?= $e(date('d/m/Y H:i:s T',$view['at'])) ?>. Contadores são do daemon, não histórico vitalício. Jail carregada não comprova cobertura efetiva do firewall; consulte <a href="<?= $e($modulelink.'&action=protection') ?>">Proteção</a>.</p>
<form method="get" class="form-inline">
    <input type="hidden" name="module" value="amssoft_fail2ban"><input type="hidden" name="action" value="jails">
    <label for="jail-search">Nome</label> <input class="form-control" id="jail-search" name="q" maxlength="64" value="<?= $e($s['q']) ?>">
    <label for="jail-state">Estado</label> <select class="form-control" id="jail-state" name="state">
    <?php foreach(['all'=>'Todas','loaded'=>'Carregadas','enabled'=>'Configuração habilitada','disabled'=>'Configuração desabilitada'] as $key=>$label): ?>
    <option value="<?= $e($key) ?>" <?= $s['state']===$key?'selected':'' ?>><?= $e($label) ?></option>
    <?php endforeach; ?></select> <button class="btn btn-default" type="submit">Filtrar</button>
</form>
<?php if(!$s['rows']): ?>
<p class="alert alert-info"><?= !$ready?'A consulta está incompleta; ausência de linhas não confirma ausência de jails.':'Nenhuma jail corresponde ao filtro.' ?></p>
<?php else: ?>
<div class="table-responsive"><table class="table table-striped table-hover">
<caption>Jails por nome em ordem estável. <?= (int)$s['filtered'] ?> resultado(s), página <?= (int)$s['page'] ?> de <?= (int)$s['pages'] ?>.</caption>
<thead><tr><th scope="col">Jail e filtro</th><th scope="col">Configuração</th><th scope="col">Daemon</th><th scope="col">Bloqueios</th><th scope="col">Tentativas</th><th scope="col">Janela e duração</th><th scope="col">Ações</th></tr></thead><tbody>
<?php foreach($s['rows'] as $jail):
 $cfg=$snapshot['effective'][$jail]??null;$enabled=$cfg!==null?JailAdmin::enabled($cfg):null;
 $loaded=$view['names']===null?null:in_array($jail,$view['names'],true);
 $status=$view['statuses'][$jail]??null;$token=$view['previews'][$jail]??'';
 $local=$snapshot['local'][$jail]??null;
 ?>
<tr data-jail="<?= $e($jail) ?>">
 <th scope="row"><?= $e($jail) ?><small class="help-block"><?= $e($cfg['filter']??'Filtro não confirmado') ?></small></th>
 <td><?= $enabled===null?'Não confirmada':($enabled?'Habilitada':'Desabilitada') ?>
 <small class="help-block">jail.local: <?= $e($local['enabled']??'herdado') ?>. Outros arquivos podem prevalecer.</small></td>
 <td><?= $loaded===null?'Não confirmado':($loaded?'Carregada':'Não carregada') ?><?= $loaded&&$status===null?' · contadores indisponíveis':'' ?>
 <?php if($enabled!==null&&$loaded!==null&&$enabled!==$loaded): ?><strong class="text-danger">Divergência</strong><?php endif; ?></td>
 <td><?= $status===null?'—':(int)$status['currently_banned'] ?><small class="help-block">Total desde carga: <?= $status===null?'não medido':(int)$status['total_banned'] ?></small></td>
 <td><?= $status===null?'—':(int)$status['currently_failed'] ?><small class="help-block">Total desde carga: <?= $status===null?'não medido':(int)$status['total_failed'] ?></small></td>
 <td>maxretry: <?= $e($cfg['maxretry']??'—') ?><br>findtime: <?= $e($cfg['findtime']??'—') ?><br>bantime: <?= $e(($cfg['bantime']??'')==='-1'?'permanente':($cfg['bantime']??'—')) ?><small class="help-block">Número sem unidade = segundos; m = minutos, h = horas, d = dias.</small></td>
 <td>
 <?php if($cfg!==null): ?><a class="btn btn-xs btn-primary" href="<?= $e($modulelink.'&action=jail_edit&jail='.rawurlencode($jail)) ?>">Editar</a><?php endif; ?>
 <button type="button" class="btn btn-xs btn-warning amsfb-jail-action" data-jail="<?= $e($jail) ?>" data-do="<?= $enabled?'disable':'enable' ?>" data-preview="<?= $e($token) ?>" <?= $token===''||$cfg===null?'disabled':'' ?>><?= $enabled?'Desabilitar':'Habilitar' ?></button>
 <?php if($local!==null): ?><button type="button" class="btn btn-xs btn-danger amsfb-jail-action" data-jail="<?= $e($jail) ?>" data-do="remove" data-preview="<?= $e($token) ?>" <?= $token===''?'disabled':'' ?>>Remover seção local</button><?php else: ?><small class="help-block">Sem seção local para remover.</small><?php endif; ?>
 </td>
</tr>
<?php endforeach; ?></tbody></table></div>
<nav aria-label="Páginas de jails"><ul class="pagination pagination-sm">
<?php if($s['page']>1): ?><li><a href="<?= $e($url($s['page']-1)) ?>" aria-label="Página anterior">«</a></li><?php endif; ?>
<?php for($p=max(1,$s['page']-3);$p<=min($s['pages'],$s['page']+3);$p++): ?>
<li class="<?= $p===$s['page']?'active':'' ?>"><a href="<?= $e($url($p)) ?>" <?= $p===$s['page']?'aria-current="page"':'' ?>><?= $p ?></a></li>
<?php endfor; ?>
<?php if($s['page']<$s['pages']): ?><li><a href="<?= $e($url($s['page']+1)) ?>" aria-label="Próxima página">»</a></li><?php endif; ?>
</ul></nav>
<?php endif; ?>
<div class="alert alert-info">Desabilitar pode remover bloqueios desta jail. Remover a seção de jail.local pode revelar uma definição herdada e até reativá-la. Nenhuma dessas ações exclui filtros padrão, cria whitelist ou impede que outra jail bloqueie o IP.</div>
<details <?= $prefill['new_jail']!==''?'open':'' ?>><summary>Nova jail</summary>
<form method="post" action="<?= $e($modulelink.'&action=jails') ?>" class="amsfb-jail-form">
<fieldset <?= !$ready?'disabled':'' ?>>
<input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>"><input type="hidden" name="do" value="add"><input type="hidden" name="preview" value="<?= $e($view['add_preview']) ?>">
<div class="form-group"><label for="new-jail">Nome da jail</label><input id="new-jail" class="form-control" name="new_jail" required maxlength="64" pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}" value="<?= $e($prefill['new_jail']) ?>"></div>
<div class="form-group"><label for="new-filter">Filtro existente</label><select id="new-filter" name="filter" class="form-control" required><option value="">Selecione</option>
<?php foreach($filters as $filter): ?><option value="<?= $e($filter) ?>" <?= $prefill['filter']===$filter?'selected':'' ?>><?= $e($filter) ?></option><?php endforeach; ?></select>
<?php if($prefill['filter']!==''&&!in_array($prefill['filter'],$filters,true)): ?><p class="text-warning">O filtro sugerido não existe. Crie e valide o filtro antes de criar a jail.</p><?php endif; ?></div>
<div class="form-group"><label for="new-logpath">Logpath único em /var/log</label><input id="new-logpath" name="logpath" class="form-control" value="<?= $e($prefill['logpath']) ?>"></div>
<?php foreach(['maxretry'=>'Tentativas de 1 a 100','findtime'=>'Janela em segundos de 60 a 86400','bantime'=>'Ban em segundos de 60 a 31536000; -1 permanente'] as $key=>$label): ?>
<div class="form-group"><label for="new-<?= $e($key) ?>"><?= $e($label) ?></label><input type="text" id="new-<?= $e($key) ?>" name="<?= $e($key) ?>" class="form-control" required value="<?= $e($prefill[$key]) ?>"></div>
<?php endforeach; ?>
<div class="checkbox"><label><input type="checkbox" name="enabled" value="1" checked> Habilitar após validar</label></div>
<div class="checkbox"><label><input type="checkbox" name="confirm" value="1" required> Confirmo a criação e o reload nativo necessário.</label></div>
<button type="submit" class="btn btn-success">Criar e validar jail</button>
</fieldset></form></details>
<noscript><p>Criação e edição funcionam por formulário. Habilitar/desabilitar pode ser feito pelo formulário Editar; ações rápidas exigem JavaScript.</p></noscript>
</div>
<script src="<?= $e($asset_base.'/js/jails.js?v=2.2.42') ?>" defer></script>
