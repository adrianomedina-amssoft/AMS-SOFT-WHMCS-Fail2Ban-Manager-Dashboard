<?php // Dedicated view keeps in-flight legacy requests compatible during publication.
$labels=['invalid'=>'Inválido','blocked'=>'Não permitido','missing'=>'Ausente','unknown'=>'Não confirmado','not_file'=>'Não é arquivo','readable'=>'Legível','unreadable'=>'Sem leitura web']; ?>
<div id="amsfb-logpaths" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>">
<div class="amsfb-page-header"><h3>Caminhos de logs</h3></div>
<p>Cadastros para o <a href="<?= $e($modulelink.'&action=logviewer') ?>">visualizador de logs</a>. Adicionar ou remover aqui não edita arquivos, permissões, jails ou fontes da IA.</p>
<p class="text-muted">A coluna de catálogo indica somente se o caminho real é uma origem aprovada para IA; não confirma seleção, coleta ativa ou proteção.
 Confira fontes e automação em <a href="<?= $e($modulelink.'&action=protection') ?>">Proteção</a> e logpaths nativos em <a href="<?= $e($modulelink.'&action=jails') ?>">Jails</a>.
 O log operacional do Fail2Ban é apenas para visualização. Leitura abaixo é a permissão do usuário web, não do coletor root.</p>
<?php if($view['error']): ?><div class="alert alert-warning" role="alert"><?= $e($view['error']) ?></div><?php endif; ?>
<div class="panel panel-default"><div class="panel-heading"><strong>Adicionar cadastro personalizado</strong></div><div class="panel-body">
<form id="amsfb-logpath-add" method="post" action="<?= $e($modulelink.'&action=logpaths') ?>">
<fieldset <?= $view['total']===null?'disabled':'' ?>>
<input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>"><input type="hidden" name="do" value="add">
<div class="row"><div class="col-sm-4 form-group"><label for="amsfb-new-label">Nome do cadastro</label>
<input id="amsfb-new-label" name="label" class="form-control" required maxlength="64" pattern="[a-zA-Z0-9][a-zA-Z0-9 _\-]{0,63}" aria-describedby="amsfb-label-help">
<small id="amsfb-label-help" class="help-block">Letras sem acento, números, espaços, hífen e underscore. Exemplo: Meu App vira meu-app. Nomes existentes não são sobrescritos.</small></div>
<div class="col-sm-8 form-group"><label for="amsfb-new-path">Arquivo em /var/log/</label>
<input id="amsfb-new-path" name="path" class="form-control" required maxlength="500" placeholder="/var/log/meuapp.log" aria-describedby="amsfb-path-help">
<small id="amsfb-path-help" class="help-block">Arquivo regular .log ou .txt, rotações numéricas ou logs de sistema permitidos. Não aceita glob, diretório ou destino fora de /var/log/. Validar não lê conteúdo.</small></div></div>
<button id="amsfb-validate-new" type="button" class="btn btn-default">Validar caminho</button>
<button type="submit" class="btn btn-primary">Adicionar cadastro</button>
<p id="amsfb-new-val-result" role="status" aria-live="polite" style="margin-top:10px;overflow-wrap:anywhere"></p>
<small class="text-muted">Até 500 cadastros. A validação é refeita ao salvar; cadastro não concede leitura nem ativa análise automática.</small>
</fieldset></form></div></div>

<?php foreach(['auto'=>'Catálogo de caminhos conhecidos','custom'=>'Cadastros personalizados'] as $kind=>$title): ?>
<div class="panel panel-default"><div class="panel-heading"><strong><?= $e($title) ?></strong></div>
<?php if($kind==='auto'): ?><p class="panel-body text-muted">Alguns caminhos podem não existir neste servidor. Catálogo automático não pode ser removido por esta tela.</p><?php endif; ?>
<?php if($kind==='custom'&&$view['total']===null): ?><p class="panel-body">Cadastros não medidos.</p>
<?php elseif(!$view[$kind]): ?><p class="panel-body text-muted">Nenhum cadastro personalizado.</p>
<?php else: ?>
<div class="table-responsive"><table class="table table-striped amsfb-table"><caption class="sr-only"><?= $e($title) ?></caption>
<thead><tr><th scope="col">Nome</th><th scope="col">Caminho</th><th scope="col">Leitura web</th><th scope="col">Tamanho</th><th scope="col">Catálogo da IA</th><th scope="col">Ações</th></tr></thead><tbody>
<?php foreach($view[$kind] as $row): ?>
<tr><td><?= $e($row['label']) ?></td><td style="overflow-wrap:anywhere"><code><?= $e($row['path']) ?></code>
<?php if($row['canonical']!==null&&$row['canonical']!==$row['path']): ?><small class="help-block">Destino: <?= $e($row['canonical']) ?></small><?php endif; ?></td>
<td><span class="<?= $row['readable']?'text-success':'text-muted' ?>"><?= $e($labels[$row['status']]??'Não confirmado') ?></span><small class="help-block"><?= $e($row['message']) ?></small></td>
<td><?= $row['size']===null?'não medido':$e(\AMS\Fail2Ban\Helper::fmtBytes($row['size'])) ?></td>
<td><?= $row['approved_source']?'Origem aprovada (não confirma coleta)':($row['canonical']===null?'Não confirmado':'Fora do catálogo de IA') ?></td>
<td><?php if($row['readable']): ?><a class="btn btn-xs btn-default" href="<?= $e($modulelink.'&action=logviewer') ?>">Abrir visualizador</a><?php endif; ?>
<?php if($kind==='custom'): ?><form method="post" class="amsfb-logpath-delete" action="<?= $e($modulelink.'&action=logpaths') ?>" style="margin-top:6px">
<input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>"><input type="hidden" name="do" value="delete">
<input type="hidden" name="id" value="<?= $e($row['id']) ?>"><input type="hidden" name="preview" value="<?= $e($row['preview']) ?>">
<label><input type="checkbox" name="confirm" value="1" required> Remover apenas este cadastro</label>
<button type="submit" class="btn btn-xs btn-danger">Remover referência</button></form><?php endif; ?></td></tr>
<?php endforeach; ?></tbody></table></div><?php endif; ?>
<?php if($kind==='custom'&&$view['total']!==null): ?><div class="panel-footer">
<?= $e($view['total']) ?> cadastro(s) — página <?= $e($view['page']) ?> de <?= $e($view['pages']) ?>.
<?php if($view['page']>1): ?><a class="btn btn-xs btn-default" href="<?= $e($modulelink.'&action=logpaths&page='.($view['page']-1)) ?>">Anterior</a><?php endif; ?>
<?php if($view['page']<$view['pages']): ?><a class="btn btn-xs btn-default" href="<?= $e($modulelink.'&action=logpaths&page='.($view['page']+1)) ?>">Próxima</a><?php endif; ?>
</div><?php endif; ?></div><?php endforeach; ?>
<noscript><p>Cadastro e remoção funcionam sem JavaScript e são validados no servidor. O botão de pré-validação exige JavaScript.</p></noscript>
</div><script src="<?= $e($asset_base.'/js/logpaths.js?v=2.2.45') ?>" defer></script>
