(function(){'use strict';
document.addEventListener('DOMContentLoaded',function(){
 var root=document.getElementById('amsfb-settings');if(!root)return;
 var form=document.getElementById('amsfb-settings-form'),result=document.getElementById('amsfb-settings-result'),save=document.getElementById('amsfb-save-btn'),reload=document.getElementById('amsfb-settings-reload'),version=document.getElementById('amsfb-settings-version');
 var busy=false,blocked=false,dirty=false,prompt=document.getElementById('amsfb-ai-prompt');
 function note(text){result.textContent=text;}
 function buttons(lock){busy=lock;Array.from(root.querySelectorAll('input,select,textarea,button')).forEach(function(el){
  if(el===reload)return;
  if(lock){el.dataset.disabledBefore=el.disabled?'1':'0';el.disabled=true;}
  else if(!blocked&&el.dataset.disabledBefore!==undefined){el.disabled=el.dataset.disabledBefore==='1';delete el.dataset.disabledBefore;}
 });}
 function bytes(){var count=new TextEncoder().encode(prompt.value).length;document.getElementById('settings-prompt-size').textContent=count+' / 8.000 bytes UTF-8.';return count;}
 form.addEventListener('input',function(){dirty=true;bytes();});form.addEventListener('change',function(){dirty=true;});
 window.addEventListener('beforeunload',function(event){if(dirty||busy){event.preventDefault();event.returnValue='';}});
 reload.addEventListener('click',function(){if((dirty||busy)&&!window.confirm('Atualizar descarta edições não salvas e não cancela operação iniciada. Continuar?'))return;dirty=false;busy=false;window.location.reload();});
 function request(action,data,timeout){
  var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},timeout||30000);
  return fetch(root.dataset.moduleLink+'&action=ai_settings&do='+action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},
   body:new URLSearchParams(Object.assign({},data,{csrf_token:(window.AMSFB&&window.AMSFB.csrfToken)||root.dataset.csrf})).toString(),signal:controller.signal})
   .then(function(r){if(!r.ok)throw new Error('HTTP');return r.json();})
   .then(function(data){if(!data||typeof data.success!=='boolean')throw new Error('JSON');if(typeof data.csrf_token==='string'&&data.csrf_token){root.dataset.csrf=data.csrf_token;if(window.AMSFB)window.AMSFB.csrfToken=data.csrf_token;}return data;})
   .finally(function(){clearTimeout(timer);});
 }
 function uncertain(){blocked=true;note('Resultado não confirmado. A operação pode ter iniciado; consulte os valores salvos e Proteção antes de repetir. Nenhum pedido será reenviado automaticamente. O rascunho continua visível.');}
 form.addEventListener('submit',function(event){
  event.preventDefault();if(busy||blocked)return;if(!form.reportValidity())return;
  if(bytes()>8000){note('Prompt excede 8.000 bytes UTF-8. Ajuste antes de salvar.');return;}
  var data={};new FormData(form).forEach(function(value,key){if(key!=='csrf_token')data[key]=value;});
  if(typeof data.ai_prompt==='string'){try{data.ai_prompt_b64=window.btoa(unescape(encodeURIComponent(data.ai_prompt)));delete data.ai_prompt;}catch(e){note('Prompt não pôde ser codificado como UTF-8.');return;}}
  if(!window.confirm('Salvar provedor, credenciais, prompt e whitelist enviados? A política de bloqueio permanece em Proteção.'))return;
  buttons(true);note('Salvando. Aguarde; não reenvie.');
  request('save_settings',data,45000).then(function(response){
   if(response.success){
    if(typeof response.policy_version!=='string'||!/^[0-9]+$/.test(response.policy_version))throw new Error('Version');
    version.value=response.policy_version;Array.from(form.querySelectorAll('input[type=password]')).forEach(function(el){el.value='';});
    dirty=false;blocked=true;note((response.message||'Salvo.')+' Atualize para conferir o estado e obter novas confirmações.');
   }else{blocked=response.code==='policy_conflict'||response.reload_required===true;note((response.error||'Salvamento recusado.')+(blocked?' Atualize antes de salvar novamente; preserve seu rascunho.':''));}
  }).catch(uncertain).finally(function(){buttons(false);});
 });
 Array.from(root.querySelectorAll('.settings-test')).forEach(function(button){button.addEventListener('click',function(){
  if(busy||blocked)return;
  if(!root.dataset.testToken){note('Confirmação de teste já usada. Recarregue antes de testar novamente.');return;}
  if(!window.confirm('Este teste envia uma mensagem sintética ao provedor e pode consumir tokens. Usa os valores digitados, não salva configurações nem envia logs. Continuar?'))return;
  var provider=button.dataset.provider,model=document.getElementById('settings-model-'+provider),key=document.getElementById('settings-key-'+provider),effort=document.getElementById('settings-effort-'+provider);
  var data={provider:provider,model:model.value,api_key:key.value,reasoning_effort:effort?effort.value:'',policy_version:version.value,confirm_test:'1',test_token:root.dataset.testToken};
  root.dataset.testToken='';buttons(true);note('Testando uma vez. Aguarde; não repita.');
  request('ping_api',data,30000).then(function(response){
   if(typeof response.test_token==='string'&&/^[0-9a-f]{64}$/.test(response.test_token))root.dataset.testToken=response.test_token;
   note((response.message||response.error||'Teste não confirmado.')+(response.observed_at?' '+response.observed_at:'')+(!root.dataset.testToken?' Recarregue antes de outro teste.':''));
  }).catch(uncertain).finally(function(){buttons(false);});
 });});
 document.getElementById('settings-preview-btn').addEventListener('click',function(){
  if(busy||blocked)return;buttons(true);note('Consultando prévia salva local; sem API.');
  request('preview_prompt',{policy_version:version.value},30000).then(function(data){
   if(!data.success||!data.preview||typeof data.preview.system!=='string')throw new Error('Preview');
   document.getElementById('settings-preview').textContent=data.preview.system;note('Prévia das instruções salvas consultada. Edições não salvas não aparecem nela.');
  }).catch(function(){note('Prévia indisponível ou configuração alterada. Nenhum dado foi salvo e nenhuma chamada ao provedor foi solicitada.');}).finally(function(){buttons(false);});
 });
 function geo(id,action,body,message){document.getElementById(id).addEventListener('click',function(){
  if(busy||blocked||!window.confirm(message))return;buttons(true);note('Solicitação GeoIP enviada.');
  request(action,body,15000).then(function(data){note(data.message||data.error||'Resultado não confirmado.');}).catch(uncertain).finally(function(){buttons(false);});
 });}
 geo('settings-geo-test','ping_geoip',{confirm_external:'1'},'Consultar o serviço externo GeoIP usando um IP sintético? Pode consumir quota, sem enviar seus logs.');
 geo('settings-geo-clear','clear_geoip_cache',{confirm_clear:'1'},'Remover todo o cache geográfico? Os bans, logs, whitelist e decisões não serão removidos. A localização pode ficar indisponível até novo enriquecimento.');
 bytes();
});
})();
