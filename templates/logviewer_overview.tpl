<div id="amsfb-viewer" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>" data-analysis-token="<?= $e($view['analysis_token']) ?>" data-analysis-lines="<?= $e($view['analysis_lines']) ?>">
<div class="amsfb-page-header"><h3>Visualizador de logs</h3></div>
<p>Amostra das últimas linhas completas, limitada a 256 KiB. O filtro pesquisa somente a amostra exibida, não todo o arquivo. Cores são indicações textuais, não confirmação de ataque ou bloqueio.</p>
<p class="text-muted">Leitura com permissões web e localização somente em cache. Pausar esta tela não pausa Fail2Ban ou IA. <a href="<?= $e($modulelink.'&action=logpaths') ?>">Gerenciar caminhos</a>.</p>
<?php foreach($view['warnings'] as $warning): ?><div class="alert alert-warning" role="status"><?= $e($warning) ?></div><?php endforeach; ?>
<div class="row"><div class="col-sm-6 form-group"><label for="viewer-path">Arquivo</label><select id="viewer-path" class="form-control">
<?php $selected=false;foreach($view['logs'] as $log):$usable=$log['valid']&&$log['readable']; ?>
<option value="<?= $e($log['path']) ?>" data-analyze="<?= $log['can_analyze']?'1':'0' ?>" <?= !$usable?'disabled':(!$selected?'selected':'') ?>><?= $e($log['label'].' — '.$log['path'].(!$usable?' ['.$log['message'].']':'')) ?></option>
<?php if($usable)$selected=true;endforeach; ?></select></div>
<div class="col-sm-2 form-group"><label for="viewer-lines">Últimas linhas</label><select id="viewer-lines" class="form-control"><?php foreach([50,100,200,500,1000] as $count): ?><option value="<?= $e($count) ?>" <?= $count===100?'selected':'' ?>><?= $e($count) ?></option><?php endforeach; ?></select></div>
<div class="col-sm-4 form-group"><label for="viewer-filter">IP ou termo nesta amostra</label><input id="viewer-filter" class="form-control" maxlength="200" placeholder="Filtro local, sem nova consulta"></div></div>
<div><button type="button" id="viewer-refresh" class="btn btn-default">Atualizar agora</button> <button type="button" id="viewer-pause" class="btn btn-warning" aria-pressed="false">Pausar atualização</button> <button type="button" id="viewer-analyze" class="btn btn-primary">Solicitar análise manual</button></div>
<p class="text-muted" style="margin-top:10px">Análise manual pode consumir tokens e salvar sugestões, sem ban imediato. Usa o limite configurado de <?= $e($view['analysis_lines']) ?> linhas e as validações do motor, não o filtro visual. O motor exclui IPs protegidos antes do provedor; a automação normal permanece independente desta tela.</p>
<p id="viewer-status" role="status" aria-live="polite">Aguardando leitura.</p><p id="viewer-count" class="text-muted"></p>
<div id="viewer-warnings" role="status" class="text-warning"></div>
<div id="viewer-output" class="amsfb-log-container" tabindex="0" role="region" aria-label="Linhas do log"></div>
<p id="viewer-analysis-result" role="status" aria-live="polite"></p>
<noscript><p class="alert alert-warning">A leitura interativa exige JavaScript. Nenhuma análise ou alteração é executada ao abrir esta página.</p></noscript>
</div><script src="<?= $e($asset_base.'/js/logviewer.js?v=2.2.47') ?>" defer></script>
