<h3>Revisão técnica de evidências</h3>
<p>Reenviar não bane nesta tela. Evidências fora da memória não podem ser reutilizadas; o histórico permanece consultável. Até 25 tarefas por página.</p>
<p><a href="<?= $e($modulelink.'&action=protection&review_view=recent#protection-maintenance') ?>" <?= $reviewView==='recent'?'aria-current="page"':'' ?>>Revisões na memória (<?= (int)$reviewCounts['recent'] ?>)</a> · <a href="<?= $e($modulelink.'&action=protection&review_view=history#protection-maintenance') ?>" <?= $reviewView==='history'?'aria-current="page"':'' ?>>Histórico de revisão (<?= (int)$reviewCounts['history'] ?>)</a></p>
<div class="table-responsive"><table class="table"><thead><tr><th>IP e origem</th><th>Horário</th><th>Diagnóstico</th><th>Ação</th></tr></thead><tbody>
<?php foreach($reviewTasks as $task):$eligibility=$task->_requeue??\AMS\Fail2Ban\BehaviorStore::requeueEligibility((array)$task,time(),(int)$values['ai_behavior_hours']); ?>
<tr><td><?= $e($task->ip) ?><br><?= $e($task->source_log) ?></td><td><?= $e($task->bucket) ?></td><td><?= $e($code($task->failure_code??'')) ?> <code><?= $e($task->failure_code) ?></code><br><?= $e($task->failure_detail) ?><br>Falhas acumuladas: <?= isset($task->total_validation_attempts)?(int)$task->total_validation_attempts:'não medido' ?> · geração <?= $e($task->recovery_generation??'nenhuma') ?> / <?= (int)($task->recovery_rounds??0) ?></td><td><button type="button" class="btn btn-default queue-requeue" data-task="<?= $e($task->id) ?>" <?= $eligibility['allowed']?'':'disabled' ?>>Reenviar para análise</button><small class="help-block"><?= $e($eligibility['reason']) ?></small></td></tr>
<?php endforeach ?>
<?php if(!count($reviewTasks)): ?><tr><td colspan="4">Nenhuma revisão neste recorte.</td></tr><?php endif ?>
</tbody></table></div>
<nav aria-label="Páginas de revisão"><span>Página <?= (int)$reviewPage ?> de <?= (int)$reviewPages ?></span><?php foreach(['Anterior'=>$reviewPage-1,'Próxima'=>$reviewPage+1] as $label=>$page):if($page<1||$page>$reviewPages)continue; ?><a class="btn btn-default btn-sm" href="<?= $e($modulelink.'&action=protection&review_view='.$reviewView.'&review_page='.$page.'#protection-maintenance') ?>"><?= $e($label) ?></a><?php endforeach ?></nav>
<h3>Manutenção pontual</h3>
<p>O GET desta página não limpa registros nem desbloqueia IPs. A prévia congela alvos por cinco minutos. Após confirmação explícita, o cron executa com backup privado e preserva bans/registros novos.</p>
<div id="amsfb-maintenance">
<p>Limites por prévia: 10.000 registros históricos, 10.000 tickets e 1 MiB de dados. Em excesso, reduza a data de corte, as tabelas ou o escopo de jails; nada será selecionado parcialmente. Monitoramento e desbloqueio não selecionam histórico para limpeza.</p>
<div class="form-group"><label for="maintenance-kind">Operação</label><select id="maintenance-kind" class="form-control"><option value="monitor">Somente acompanhar</option><option value="archive">Arquivar e limpar histórico operacional</option><option value="unban">Desbloquear alvos</option><option value="both">Arquivar/limpar e desbloquear</option></select></div>
<div data-unban-controls hidden>
<div class="form-group"><label for="maintenance-scope">Escopo dos desbloqueios</label><select id="maintenance-scope" class="form-control"><option value="ai">Jails da IA</option><option value="all">Todas as jails do Fail2Ban</option><option value="selected">Jails selecionadas</option></select></div>
<div data-selected-jails hidden><label for="maintenance-jails">Jails selecionadas, separadas por vírgula</label><input id="maintenance-jails" class="form-control"></div>
</div>
<div data-archive-controls hidden>
<p class="alert alert-warning">Arquivamento/limpeza abrange o histórico operacional do módulo nas categorias marcadas, independentemente das jails escolhidas para desbloquear. Não apaga os logs originais, configurações, chaves ou whitelist.</p>
<label for="maintenance-cutoff">Data de corte do histórico, vazio significa agora</label><input id="maintenance-cutoff" type="datetime-local" class="form-control">
<label><input id="maintenance-logs" type="checkbox" checked> Histórico operacional</label>
<label><input id="maintenance-suggestions" type="checkbox" checked> Sugestões antigas</label>
<label><input id="maintenance-observations" type="checkbox" checked> Observações e agregações antigas</label>
</div>
<div data-optional-monitor hidden><label><input id="maintenance-monitor" type="checkbox" checked> Iniciar acompanhamento após a operação</label></div>
<p>Acompanhamento configurado: <?= (int)$values['monitor_hours'] ?> horas, intervalo mínimo de <?= (int)$values['monitor_interval'] ?> segundos, independente do navegador.</p>
<button type="button" id="maintenance-preview" class="btn btn-default">Gerar prévia</button>
<p id="maintenance-status" role="status" aria-live="polite"></p>
<div id="maintenance-preview-summary" hidden></div>
<details><summary>Resposta técnica da última operação</summary><pre id="maintenance-output"></pre></details>
<label for="maintenance-confirm">Para confirmar, digite EXECUTAR MANUTENCAO</label><input id="maintenance-confirm" autocomplete="off" class="form-control">
<button type="button" id="maintenance-queue" class="btn btn-warning" disabled>Confirmar e enfileirar</button>
</div>
<?php $failedJobs=array_filter($jobs,fn($job)=>$job['status']==='failed');if($failedJobs): ?><h4>Retomadas de trabalhos com falha</h4><p>Revise a falha no Histórico, digite a frase acima e use a retomada. O servidor revalida autoria, versão e integridade do backup; o escopo não é ampliado.</p><?php foreach($failedJobs as $job): ?><p><code><?= $e($job['id']) ?></code> <button type="button" class="btn btn-warning maintenance-retry" data-job="<?= $e($job['id']) ?>">Retomar escopo congelado</button></p><?php endforeach ?><?php endif ?>
