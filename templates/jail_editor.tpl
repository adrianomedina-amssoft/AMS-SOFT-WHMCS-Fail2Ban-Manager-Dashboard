<?php $cfg=$snapshot['effective'][$jail]??[]; ?>
<div id="amsfb-jails-view" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>">
<h3>Editar jail <?= $e($jail) ?></h3>
<a href="<?= $e($modulelink.'&action=jails') ?>">Voltar para jails</a>
<div id="amsfb-jails-notice" role="status" tabindex="-1" hidden></div>
<?php if($error): ?><div class="alert alert-warning"><?= $e($error) ?></div>
<?php else: ?>
<p class="alert alert-info">Valores efetivos calculados pelo Fail2Ban, não uma comprovação dos parâmetros carregados. Alterações são gravadas em jail.local; overrides e quarentenas permanecem. Desabilitar pode retirar os bloqueios desta jail. O salvamento faz validação e reload nativo.</p>
<details><summary>Valores solicitados em jail.local</summary><pre><?= $e(json_encode($snapshot['local'][$jail]??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre></details>
<form method="post" action="<?= $e($modulelink.'&action=jail_edit&jail='.rawurlencode($jail)) ?>" class="amsfb-jail-form" style="max-width:760px">
<input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>"><input type="hidden" name="do" value="save"><input type="hidden" name="jail" value="<?= $e($jail) ?>"><input type="hidden" name="preview" value="<?= $e($preview) ?>">
<div class="checkbox"><label><input type="checkbox" name="enabled" value="1" <?= \AMS\Fail2Ban\JailAdmin::enabled($cfg)?'checked':'' ?>> Habilitada na configuração</label></div>
<?php foreach(['maxretry'=>'Tentativas de 1 a 100','findtime'=>'Janela de observação','bantime'=>'Duração do bloqueio; -1 permanente'] as $key=>$label): ?>
<div class="form-group"><label for="edit-<?= $e($key) ?>"><?= $e($label) ?></label><input type="text" class="form-control" id="edit-<?= $e($key) ?>" name="<?= $e($key) ?>" value="<?= $e($cfg[$key]??'') ?>" required></div>
<?php endforeach; ?>
<p class="help-block">Valores nativos existentes (ex.: 10m, 48h) são preservados sem conversão. Ao alterar: findtime entre 60 e 86400 segundos; bantime entre 60 e 31536000 segundos ou -1. Use números inteiros.</p>
<div class="form-group"><label for="edit-logpath">Arquivos de log efetivos</label><textarea class="form-control" rows="5" id="edit-logpath" name="logpath"><?= $e($cfg['logpath']??'') ?></textarea>
<p class="help-block">Múltiplos caminhos existentes são preservados se não forem editados. Alteração por esta tela aceita um único caminho em /var/log; não concatena nem apaga silenciosamente valores.</p></div>
<div class="checkbox"><label><input type="checkbox" name="confirm" value="1" required> Confirmo os valores e o impacto do reload; desabilitar pode liberar bloqueios desta jail.</label></div>
<button type="submit" class="btn btn-primary">Salvar e validar</button>
</form>
<?php endif; ?>
</div>
<script src="<?= $e($asset_base.'/js/jails.js?v=2.2.42') ?>" defer></script>
