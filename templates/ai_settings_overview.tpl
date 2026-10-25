<?php $policy=$view['policy'];$defs=\AMS\Fail2Ban\Policy::fields(); ?>
<div id="amsfb-settings" data-module-link="<?= $e($modulelink) ?>" data-csrf="<?= $e($csrf_token) ?>" data-test-token="<?= $e($view['test_token']) ?>">
<div class="amsfb-page-header"><h3>Configurações da IA</h3>
<a class="btn btn-default btn-sm" href="<?= $e($modulelink.'&action=ai') ?>">Decisões e análise manual</a>
<a class="btn btn-default btn-sm" href="<?= $e($modulelink.'&action=protection') ?>">Proteção e manutenção</a></div>
<p>Esta tela edita provedores, credenciais, whitelist e prompt. Critérios de bloqueio, coleta, aprendizado e orçamento são ajustados em Proteção. Abrir ou salvar esta tela não executa análise de logs.</p>
<div id="amsfb-settings-result" class="alert alert-info" role="status" aria-live="polite">Valores salvos, versão <?= $e($view['version']) ?>. Nenhuma API foi consultada nesta abertura.</div>
<button type="button" id="amsfb-settings-reload" class="btn btn-default btn-sm">Atualizar configuração salva</button>
<?php foreach($view['warnings'] as $warning): ?><p class="alert alert-warning"><?= $e($warning) ?></p><?php endforeach ?>
<details><summary>Política atual de proteção e consumo — somente leitura</summary>
<p>Alterações nesses critérios são feitas em <a href="<?= $e($modulelink.'&action=protection') ?>">Proteção e manutenção</a>. Automação não depende desta página aberta. Modo automático continua condicionado à evidência, validação nativa, whitelist e limites configurados.</p>
<table class="table table-striped"><tbody>
<?php foreach(['ai_auto_enabled','ai_mode','ai_auto_min_confidence','ai_min_confidence','ai_interval_minutes','ai_cycle_max_calls','ai_log_lines','ai_batch_max_per_session','ai_filter_min_confidence','ai_auto_create_filter','global_bantime'] as $key): ?>
<tr><th><?= $e($defs[$key][1]??$key) ?></th><td><?= $e($policy[$key]??'Não disponível') ?></td></tr>
<?php endforeach ?>
<tr><th>Confirmação automática registrada</th><td><?= $view['confirmed_auto']==='1'?'Sim':'Não' ?></td></tr>
</tbody></table>
<p>0/1 nos controles booleanos significa desativado/ativado. Lotes de coleta não equivalem a chamadas pagas; confiança de classificação não substitui confiança automática e prova individual. O intervalo depende da execução do cron.</p>
</details>
<form id="amsfb-settings-form" method="post" action="<?= $e($modulelink.'&action=ai_settings') ?>" autocomplete="off">
<input type="hidden" name="csrf_token" value="<?= $e($csrf_token) ?>">
<input type="hidden" name="policy_version" id="amsfb-settings-version" value="<?= $e($view['version']) ?>">
<fieldset><legend>Provedor usado na próxima análise</legend>
<label for="settings-provider">Provedor ativo</label>
<select class="form-control" id="settings-provider" name="ai_active_provider">
<?php if(!isset($view['providers'][$view['active']])): ?><option value="<?= $e($view['active']) ?>" selected>Valor salvo não reconhecido — escolha um provedor</option><?php endif ?>
<?php foreach($view['providers'] as $id=>$def): ?><option value="<?= $e($id) ?>" <?= $view['active']===$id?'selected':'' ?>><?= $e($def['label']) ?></option><?php endforeach ?>
</select>
<p>Todos os painéis abaixo são editáveis. Trocar o provedor ativo não apaga as chaves dos demais. Endpoints e protocolos são fixados pelo módulo, não pelo formulário.</p>
</fieldset>
<?php foreach($view['providers'] as $id=>$def): $cfg=$view['configs'][$id]; ?>
<fieldset class="panel panel-default settings-provider-panel" data-provider="<?= $e($id) ?>">
<legend class="panel-heading"><?= $e($def['label']) ?></legend><div class="panel-body">
<p><?= $e($cfg['key_state']) ?></p>
<label for="settings-key-<?= $e($id) ?>">Nova chave API — vazio mantém a chave atual</label>
<input class="form-control" type="password" id="settings-key-<?= $e($id) ?>" name="ai_provider_<?= $e($id) ?>_api_key" autocomplete="new-password" maxlength="4096" value="">
<label for="settings-model-<?= $e($id) ?>">Modelo</label>
<select class="form-control" id="settings-model-<?= $e($id) ?>" name="ai_provider_<?= $e($id) ?>_model">
<?php if(!isset($def['models'][$cfg['model']])): ?><option selected value="<?= $e($cfg['model']) ?>">Valor salvo fora do catálogo: <?= $e($cfg['model']) ?></option><?php endif ?>
<?php foreach($def['models'] as $model=>$label): ?><option value="<?= $e($model) ?>" <?= $cfg['model']===$model?'selected':'' ?>><?= $e($label) ?></option><?php endforeach ?>
</select>
<?php if(!empty($def['reasoning_efforts'])): ?>
<label for="settings-effort-<?= $e($id) ?>">Raciocínio da análise</label>
<select class="form-control" id="settings-effort-<?= $e($id) ?>" name="ai_provider_<?= $e($id) ?>_reasoning_effort">
<?php if(!isset($def['reasoning_efforts'][$cfg['effort']])): ?><option selected value="<?= $e($cfg['effort']) ?>">Valor salvo não reconhecido: <?= $e($cfg['effort']) ?></option><?php endif ?>
<?php foreach($def['reasoning_efforts'] as $effort=>$label): ?><option value="<?= $e($effort) ?>" <?= $cfg['effort']===$effort?'selected':'' ?>><?= $e($label) ?></option><?php endforeach ?>
</select>
<?php endif ?>
<p>Endpoint fixo: <code><?= $e($def['default_base_url']) ?></code>. O teste usa uma mensagem sintética curta, sem logs. Pode consumir tokens; não comprova uma análise completa, o raciocínio selecionado ou disponibilidade futura.</p>
<button type="button" class="btn btn-default settings-test" data-provider="<?= $e($id) ?>">Testar este provedor — pode ter custo</button>
<span class="settings-test-result" data-provider="<?= $e($id) ?>" role="status"></span>
</div></fieldset>
<?php endforeach ?>
<fieldset><legend>Whitelist administrada pelo módulo</legend>
<label for="settings-whitelist">IPs ou redes CIDR autorizadas</label>
<textarea class="form-control" id="settings-whitelist" name="ai_whitelist_ips" rows="4" maxlength="5000"><?= $e($view['whitelist']) ?></textarea>
<p>Aceita IPv4/IPv6 e CIDR, separados por espaço, vírgula, ponto e vírgula ou quebra de linha. Alterar este campo sincroniza a política nativa. Não é um comando de desbanimento. Confirme os endereços antes de salvar.</p>
</fieldset>
<fieldset><legend>Prompt personalizado</legend>
<label for="amsfb-ai-prompt">Template com exatamente um {logs}, até 8.000 bytes UTF-8</label>
<textarea class="form-control" id="amsfb-ai-prompt" name="ai_prompt" rows="14" maxlength="8000"><?= $e($view['prompt']) ?></textarea>
<p id="settings-prompt-size" role="status"></p>
<p>O template é compartilhado entre provedores. Logs são dados não confiáveis; as regras obrigatórias e o formato do provedor são acrescentados pelo motor. País, ASN, User-Agent ou status isolado não autorizam ban ou whitelist. Alterar prompt/modelo invalida reaproveitamentos de análise, sem apagar histórico ou desbloquear IPs.</p>
<p>Rotas normais são configuradas em Proteção: não dão imunidade a descendentes sensíveis ou payload ofensivo. As barreiras de IPs protegidos continuam sendo aplicadas antes do provedor.</p>
<button type="button" id="settings-preview-btn" class="btn btn-default">Consultar instruções efetivas salvas — sem API</button>
<pre id="settings-preview" style="max-height:320px;overflow:auto;white-space:pre-wrap" aria-live="polite"></pre>
<p>A prévia usa somente os valores salvos e o inventário disponível, não as edições acima. Inventário vazio/indisponível não confirma ausência de filtros. Logs reais e contexto são acrescentados somente na execução.</p>
</fieldset>
<p><label><input type="checkbox" name="confirm_settings" value="1" required> Confirmo salvar os valores enviados. Troca de provedor, chave ou prompt afeta análises futuras; mudança de whitelist afeta a proteção nativa.</label></p>
<button type="submit" id="amsfb-save-btn" class="btn btn-primary">Salvar configurações</button>
<noscript><p>O formulário usa POST. Testes e prévia exigem JavaScript. Se ocorrer erro, as chaves digitadas não serão devolvidas em HTML; confira o rascunho antes de voltar.</p></noscript>
</form>
<hr>
<h4>GeoIP</h4>
<p>Localização vem do cache local nas telas auditadas. País não é evidência de ataque. Testar consulta um endereço sintético no serviço externo; limpar remove apenas o cache geográfico e exige confirmação.</p>
<button type="button" id="settings-geo-test" class="btn btn-default">Testar serviço externo GeoIP</button>
<button type="button" id="settings-geo-clear" class="btn btn-default">Limpar cache geográfico</button>
<p>Para analisar logs manualmente, use <a href="<?= $e($modulelink.'&action=ai') ?>">Decisões e análise manual</a>. O cron continua independente; salvar não inicia um ciclo.</p>
</div>
<script src="<?= $e($asset_base) ?>/js/ai_settings.js?v=2.2.49"></script>
