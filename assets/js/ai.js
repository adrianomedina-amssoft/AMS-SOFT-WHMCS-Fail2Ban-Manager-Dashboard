(function(){'use strict';
document.addEventListener('DOMContentLoaded',function(){
 var root=document.getElementById('amsfb-ai-view');if(!root)return;
 var result=document.getElementById('amsfb-ai-result'),run=document.getElementById('amsfb-run-now-btn'),stop=document.getElementById('amsfb-stop-btn'),refresh=document.getElementById('amsfb-ai-refresh');
 var busy=false,stale=false,stopped=false,storageKey='amsfb_ai_selection48:'+root.dataset.moduleLink,selection=[],storageAt=0;
 function items(q){return Array.from(root.querySelectorAll(q));}
 function note(text){result.textContent=text;}
 function save(){try{sessionStorage.setItem(storageKey,JSON.stringify({at:storageAt||Date.now(),ids:selection}));}catch(e){}}
 function clear(){selection=[];storageAt=Date.now();try{sessionStorage.removeItem(storageKey);}catch(e){}syncSelection();}
 function checked(){return items('.amsfb-row-cb').filter(function(cb){return !cb.disabled;});}
 function syncSelection(){
  var validView=root.dataset.view==='actionable';
  items('.amsfb-row-cb').forEach(function(cb){var id=Number(cb.dataset.id);if(cb.disabled)selection=selection.filter(function(x){return x!==id;});cb.checked=!cb.disabled&&selection.indexOf(id)>=0;});
  document.getElementById('amsfb-bulk-bar').style.display=validView&&selection.length?'':'none';
  document.getElementById('amsfb-bulk-count').textContent=selection.length+' decisão(ões) selecionada(s), incluindo outras páginas; máximo 200.';
  var all=document.getElementById('amsfb-select-all'),rows=checked();
  all.checked=rows.length>0&&rows.every(function(cb){return cb.checked;});all.indeterminate=rows.some(function(cb){return cb.checked;})&&!all.checked;
 }
 if(root.dataset.view==='actionable'){try{var stored=JSON.parse(sessionStorage.getItem(storageKey)||'null');
  if(stored&&Number.isFinite(stored.at)&&stored.at<=Date.now()&&Date.now()-stored.at<900000&&Array.isArray(stored.ids)&&stored.ids.length<=200&&stored.ids.every(function(x){return Number.isSafeInteger(x)&&x>0&&x<=9999999999;})){selection=Array.from(new Set(stored.ids));storageAt=stored.at;}
 }catch(e){}}
 function add(ids){var next=Array.from(new Set(selection.concat(ids)));if(next.length>200){note('Seleção limitada a 200 decisões. Limpe a seleção anterior antes de selecionar outro grupo.');return;}selection=next;if(!storageAt)storageAt=Date.now();save();syncSelection();}
 function lock(value){busy=value;items('button,input[type=checkbox]').forEach(function(button){
  if(button===stop||button===refresh)return;
  if(value){button.dataset.wasDisabled=button.disabled?'1':'0';button.disabled=true;}
  else if(!stale&&button.dataset.wasDisabled!==undefined){button.disabled=button.dataset.wasDisabled==='1';delete button.dataset.wasDisabled;}
 });}
 function request(action,body,timeout){
  var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},timeout||120000);
  return fetch(root.dataset.moduleLink+'&action=ai&do='+action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},body:new URLSearchParams(Object.assign({},body,{csrf_token:(window.AMSFB&&window.AMSFB.csrfToken)||root.dataset.csrf})).toString(),signal:controller.signal})
   .then(function(response){if(!response.ok)throw new Error('HTTP');return response.json();})
   .then(function(data){if(!data||typeof data.success!=='boolean')throw new Error('JSON');if(typeof data.csrf_token==='string'&&data.csrf_token){root.dataset.csrf=data.csrf_token;if(window.AMSFB)window.AMSFB.csrfToken=data.csrf_token;}return data;})
   .finally(function(){clearTimeout(timer);});
 }
 function uncertain(){stale=true;note('Resultado não confirmado. A operação pode ter iniciado; atualize os dados antes de repetir. Nenhum pedido será reenviado automaticamente.');}
 function mutate(action,body,message){
  if(busy||stale||!window.confirm(message))return;
  lock(true);note('Solicitação enviada. Aguarde; não repita.');
  request(action,body).then(function(data){
   stale=true;clear();
   note((data.message||data.error||(data.success?'Operação concluída.':'Operação não confirmada.'))+' Atualize os dados para conferir filas, contadores e resultados atuais.');
  }).catch(uncertain).finally(function(){lock(false);});
 }
 refresh.addEventListener('click',function(){if(busy&&!window.confirm('Há uma solicitação em andamento. Atualizar não garante cancelamento no servidor. Continuar?'))return;window.location.reload();});
 items('.amsfb-approve-btn').forEach(function(button){button.addEventListener('click',function(){if(!button.disabled)mutate('approve',{id:button.dataset.id},'Confirmar bloqueio da decisão #'+button.dataset.id+'? A proteção e os critérios serão revalidados.');});});
 items('.amsfb-reject-btn').forEach(function(button){button.addEventListener('click',function(){if(!button.disabled)mutate('reject',{id:button.dataset.id},'Rejeitar a decisão #'+button.dataset.id+'? Isso não remove bans existentes.');});});
 items('.amsfb-create-filter-btn').forEach(function(button){button.addEventListener('click',function(){if(!button.disabled)mutate('create_filter',{id:button.dataset.id},'Solicitar aprendizado nativo validado para a decisão #'+button.dataset.id+'? O cron avalia a solicitação; isso não garante criar ou ativar uma jail.');});});
 items('.amsfb-evidence-btn').forEach(function(button){button.addEventListener('click',function(){
  var content=document.getElementById('amsfb-evidence-content');
  try{var evidence=JSON.parse(button.dataset.evidence||'[]');content.textContent=Array.isArray(evidence)?evidence.map(function(x){return typeof x==='string'?x:JSON.stringify(x);}).join('\n'):String(evidence);}catch(e){content.textContent='Evidência indisponível nesta apresentação.';}
  if(window.jQuery)window.jQuery('#amsfb-evidence-modal').modal('show');
 });});
 items('.amsfb-rule-btn').forEach(function(button){button.addEventListener('click',function(){document.getElementById('amsfb-rule-content').textContent=button.dataset.rule||'';if(window.jQuery)window.jQuery('#amsfb-rule-modal').modal('show');});});
 items('.amsfb-row-cb').forEach(function(cb){cb.addEventListener('change',function(){if(busy||stale||cb.disabled)return;var id=Number(cb.dataset.id);if(cb.checked)add([id]);else{selection=selection.filter(function(x){return x!==id;});save();syncSelection();}});});
 document.getElementById('amsfb-select-all').addEventListener('change',function(event){if(busy||stale||event.target.disabled)return;var ids=checked().map(function(cb){return Number(cb.dataset.id);});if(event.target.checked)add(ids);else{selection=selection.filter(function(x){return ids.indexOf(x)<0;});save();syncSelection();}});
 document.getElementById('amsfb-bulk-clear-btn').addEventListener('click',clear);
 document.getElementById('amsfb-bulk-approve-btn').addEventListener('click',function(){if(selection.length)mutate('bulk_approve_ids',{ids:JSON.stringify(selection)},'Confirmar bloqueio das '+selection.length+' decisões selecionadas, incluindo outras páginas? Uma seleção desatualizada será recusada.');});
 document.getElementById('amsfb-bulk-reject-btn').addEventListener('click',function(){if(selection.length)mutate('bulk_reject_ids',{ids:JSON.stringify(selection)},'Rejeitar '+selection.length+' decisões selecionadas, incluindo outras páginas? Bans existentes permanecem.');});
 items('.amsfb-select-country').forEach(function(button){button.addEventListener('click',function(){
  if(busy||stale)return;lock(true);note('Consultando decisões atualmente acionáveis deste país, somente no cache local.');
  request('get_ids_by_country',{country_code:button.dataset.countryCode},30000).then(function(data){
   if(!data.success||!Array.isArray(data.ids)||data.ids.length>200||!data.ids.every(function(x){return Number.isSafeInteger(x)&&x>0;}))throw new Error('Selection');
   // Unlock first so disabled checkboxes don't discard valid selections.
   lock(false);add(data.ids);note(data.limited?'Há mais de 200 decisões no grupo; somente as primeiras 200 foram oferecidas.':'Seleção consultada; país sozinho não é evidência de ataque.');
  }).catch(function(){note('Seleção não confirmada; tente consultar novamente. Nenhuma decisão foi alterada.');if(busy)lock(false);});
 });});
 stop.addEventListener('click',function(){stopped=true;stop.disabled=true;note('Parando após a solicitação atual. O cron e o Fail2Ban continuam ativos.');});
 run.addEventListener('click',function(){
  if(busy||stale||run.disabled||!window.confirm('Analisar uma amostra final das fontes disponíveis? Pode consumir tokens e salvar sugestões. Não avança a coleta automática nem executa bans imediatamente. IPs protegidos são rechecados pelo motor antes do provedor.'))return;
  lock(true);stopped=false;stop.disabled=false;stop.style.display='';note('Preparando sessão manual confirmada.');
  var total=0,done=0,saved=0;
  function finish(message){stale=true;clear();stop.style.display='none';note(message+' Fontes tentadas: '+done+'/'+total+'; sugestões salvas: '+saved+'. Atualize os dados para consultar as categorias corretas.');lock(false);}
  request('list_logs',{confirm:'1'},30000).then(function(data){
   if(!data.success)throw new Error(data.error||'Sessão não iniciada.');
   if(!Array.isArray(data.logs)||data.logs.length>100||!data.logs.every(function(x){return x&&typeof x.path==='string'&&typeof x.analysis_token==='string'&&/^[0-9a-f]{64}$/.test(x.analysis_token);}))throw new Error('Catálogo inválido.');
   total=data.logs.length;var warnings=Array.isArray(data.warnings)?data.warnings.join(' '):'';
   function next(){
    if(stopped||done>=total){finish((stopped?'Novas fontes interrompidas.':'Sessão manual concluída.')+' '+warnings);return;}
    var log=data.logs[done];done++;note('Analisando fonte '+done+'/'+total+': '+log.path+'. Aguarde; não repita.');
    return request('analyze_log',{path:log.path,analysis_token:log.analysis_token,confirm:'1'}).then(function(response){
     if(!response.success){finish(response.error||response.message||'Fonte não concluída. Sessão interrompida sem repetição.');return;}
     if(!Number.isInteger(response.saved)||response.saved<0)throw new Error('Resposta inválida.');
     saved+=response.saved;return next();
    });
   }
   return next();
  }).catch(function(){stop.style.display='none';uncertain();lock(false);});
 });
 syncSelection();
});
})();
