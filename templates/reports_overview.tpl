<?php
$f=$view['filters'];
$url=static function(array $extra=[])use($modulelink,$f){return $modulelink.'&'.http_build_query(array_merge(['action'=>'reports','date_from'=>$f['date_from'],'date_to'=>$f['date_to'],'ip'=>$f['ip'],'jail'=>$f['jail'],'action_filter'=>$f['action']],$extra),'','&',PHP_QUERY_RFC3986);};
?>
<div class="amsfb-page-header"><h3>Relatórios de eventos</h3>
<?php if($view['exportable']&&!$view['errors']): ?><a class="btn btn-sm btn-success" href="<?= $e($url(['do'=>'export_csv'])) ?>">Exportar CSV filtrado</a><?php endif; ?></div>
<p>Histórico registrado pelo módulo. Um evento de banimento não confirma que o IP continua bloqueado. Confira o estado atual em <a href="<?= $e($modulelink.'&action=ips') ?>">IPs bloqueados</a>.</p>
<p class="text-muted">Localização somente do cache local, quando disponível; sem consulta externa nesta tela ou no CSV. Campos geográficos vazios não indicam ausência de ameaça.
 CSV: até 10.000 eventos e 20 MiB; volumes maiores exigem filtros, sem corte silencioso. O conteúdo exportado reflete a consulta no momento do download.</p>
<?php foreach($view['errors'] as $message): ?><div class="alert alert-danger" role="alert"><?= $e($message) ?></div><?php endforeach; ?>
<?php foreach($view['warnings'] as $message): ?><div class="alert alert-warning" role="status"><?= $e($message) ?></div><?php endforeach; ?>
<form method="get" action="<?= $e(strtok($modulelink,'?')) ?>" class="amsfb-filter-form">
<input type="hidden" name="module" value="amssoft_fail2ban"><input type="hidden" name="action" value="reports">
<div class="row">
<?php foreach(['date_from'=>'Data inicial','date_to'=>'Data final (inclusive)'] as $name=>$label): ?><div class="col-sm-3 form-group"><label for="reports-<?= $e($name) ?>"><?= $e($label) ?></label>
<input id="reports-<?= $e($name) ?>" type="date" name="<?= $e($name) ?>" class="form-control" value="<?= $e($f[$name]) ?>"></div><?php endforeach; ?>
<div class="col-sm-6 form-group"><label for="reports-ip">IP completo (correspondência exata)</label><input id="reports-ip" name="ip" class="form-control" maxlength="45" value="<?= $e($f['ip']) ?>" placeholder="IPv4 ou IPv6, sem CIDR"></div></div>
<div class="row">
<?php foreach(['jail'=>['Jail','jails',64],'action_filter'=>['Ação registrada','actions',40]] as $name=>$meta): $key=$name==='action_filter'?'action':$name; ?>
<div class="col-sm-6 form-group"><label for="reports-<?= $e($name) ?>"><?= $e($meta[0]) ?></label>
<input id="reports-<?= $e($name) ?>" name="<?= $e($name) ?>" class="form-control" maxlength="<?= $e($meta[2]) ?>" list="reports-<?= $e($meta[1]) ?>" value="<?= $e($f[$key]) ?>" placeholder="Vazio para todos" aria-describedby="reports-catalog-help">
<datalist id="reports-<?= $e($meta[1]) ?>"><?php foreach($view[$meta[1]] as $value): ?><option value="<?= $e($value) ?>"></option><?php endforeach; ?></datalist></div>
<?php endforeach; ?></div>
<p id="reports-catalog-help" class="text-muted">Sugestões do histórico; também é possível digitar um identificador exato. <?= $view['catalog_limited']?'Catálogo limitado às primeiras 200 opções por campo.':'' ?></p>
<button class="btn btn-primary" type="submit">Filtrar</button> <a class="btn btn-default" href="<?= $e($modulelink.'&action=reports') ?>">Limpar</a>
</form>
<p class="text-muted" style="margin-top:12px">Horários conforme a sessão do banco, sem conversão.
<?php if($view['clock']): ?>Fuso: <?= $e($view['clock']['session_zone']) ?> / sistema <?= $e($view['clock']['system_zone']) ?>. Consulta: <?= $e($view['clock']['db_now']) ?>.<?php endif; ?></p>
<?php if($view['total']===null): ?><p role="status">Total não confirmado. Corrija os filtros ou consulte novamente.</p>
<?php else: ?><p>Total: <strong><?= $e($view['total']) ?></strong> evento(s) filtrado(s). Página <?= $e($view['page']) ?> de <?= $e($view['pages']) ?>.</p>
<?php if(!$view['exportable']&&!$view['errors']): ?><p class="text-warning">Refine os filtros para exportar no máximo 10.000 eventos.</p><?php endif; ?>
<?php if(!$view['rows']): ?><div class="alert alert-info">Nenhum evento encontrado com os filtros aplicados.</div>
<?php else: ?><div class="table-responsive"><table class="table table-striped amsfb-table"><caption class="sr-only">Eventos históricos filtrados</caption>
<thead><tr><?php foreach(['ID','Data/hora','IP','Jail','Ação','Motivo','Admin'] as $label): ?><th scope="col"><?= $e($label) ?></th><?php endforeach; ?></tr></thead><tbody>
<?php foreach($view['rows'] as $row): ?><tr>
<td><?= $e($row['id']) ?></td><td><?= $e($row['timestamp']) ?></td><td><code><?= $e($row['ip']) ?></code>
<?php if(!empty($view['geo'][$row['ip']])): ?><br><small><?= $e(\AMS\Fail2Ban\GeoIP::formatGeo($view['geo'][$row['ip']])) ?></small><?php elseif($row['ip']!==''): ?><br><small class="text-muted">Localização não disponível no cache</small><?php endif; ?></td>
<td><?= $e($row['jail']) ?></td><td><?= $e($row['action']) ?></td>
<td style="max-width:650px;overflow-wrap:anywhere"><?php $reason=(string)($row['reason']??''); if(mb_strlen($reason)>200): ?><details><summary><?= $e(mb_substr($reason,0,160)) ?>… (ver motivo completo)</summary><div style="white-space:pre-wrap"><?= $e($reason) ?></div></details><?php else: ?><span style="white-space:pre-wrap"><?= $e($reason) ?></span><?php endif; ?></td>
<td><?= !empty($row['admin_id'])?$e($row['admin_id']):'não atribuído' ?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
<?php if($view['pages']>1): ?><nav aria-label="Paginação de eventos">
<?php if($view['page']>1): ?><a class="btn btn-default btn-sm" href="<?= $e($url(['page'=>1])) ?>">Primeira</a> <a class="btn btn-default btn-sm" href="<?= $e($url(['page'=>$view['page']-1])) ?>">Anterior</a><?php endif; ?>
<?php if($view['page']<$view['pages']): ?><a class="btn btn-default btn-sm" href="<?= $e($url(['page'=>$view['page']+1])) ?>">Próxima</a> <a class="btn btn-default btn-sm" href="<?= $e($url(['page'=>$view['pages']])) ?>">Última</a><?php endif; ?></nav><?php endif; endif; ?>
