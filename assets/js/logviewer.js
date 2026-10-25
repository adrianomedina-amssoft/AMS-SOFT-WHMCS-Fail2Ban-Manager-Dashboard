(function(){'use strict';
document.addEventListener('DOMContentLoaded',function(){
 var root=document.getElementById('amsfb-viewer');if(!root)return;
 function el(id){return document.getElementById('viewer-'+id);}
 var path=el('path'),limit=el('lines'),filter=el('filter'),out=el('output'),status=el('status'),count=el('count'),warnings=el('warnings'),result=el('analysis-result');
 var refresh=el('refresh'),pause=el('pause'),analyze=el('analyze'),paused=false,busy=false,analyzing=false,generation=0,pending=false,timer=null,active=null,cache=[],geo={},failures=0;
 function token(){return (window.AMSFB&&window.AMSFB.csrfToken)||root.dataset.csrf||'';}
 function sync(t){if(typeof t==='string'&&t){root.dataset.csrf=t;if(window.AMSFB)window.AMSFB.csrfToken=t;}}
 function available(){return path.selectedOptions&&path.selectedOptions[0]&&!path.selectedOptions[0].disabled;}
 function buttons(){analyze.disabled=analyzing||busy||!available()||path.selectedOptions[0].dataset.analyze!=='1'||!root.dataset.analysisToken;path.disabled=analyzing;limit.disabled=analyzing;refresh.disabled=analyzing;}
 function schedule(){clearTimeout(timer);if(!paused&&!document.hidden&&!analyzing)timer=setTimeout(function(){load(false);},Math.min(60000,5000*Math.pow(2,Math.min(failures,3))));}
 function request(action,body,retry,timeout){
  var controller=new AbortController();if(action==='fetch_lines')active=controller;
  var deadline=setTimeout(function(){controller.abort();},timeout);
  function send(retried){return fetch(root.dataset.moduleLink+'&action=logviewer&do='+action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},body:new URLSearchParams(Object.assign({},body,{csrf_token:token()})).toString(),signal:controller.signal})
   .then(function(response){if(!response.ok)throw new Error('HTTP');return response.json();})
   .then(function(data){if(!data||typeof data.success!=='boolean')throw new Error('JSON');sync(data.csrf_token);if(retry&&!retried&&!data.success&&typeof data.error==='string'&&/CSRF/i.test(data.error))return send(true);return data;});}
  return send(false).finally(function(){clearTimeout(deadline);});
 }
 function render(){
  var stick=out.scrollHeight-out.scrollTop-out.clientHeight<40,fragment=document.createDocumentFragment(),shown=0,term=filter.value.toLowerCase();
  cache.forEach(function(item){if(term&&item.text.toLowerCase().indexOf(term)<0)return;shown++;
   var row=document.createElement('div');row.className='amsfb-log-line amsfb-log-'+item.class;
   if(typeof item.peer==='string'&&item.peer.length<=45&&/^[0-9a-fA-F:.]+$/.test(item.peer)){
    var link=document.createElement('a');link.className='btn btn-xs btn-default';link.textContent='Revisar IP '+item.peer;link.href=root.dataset.moduleLink+'&action=ips&ban_ip='+encodeURIComponent(item.peer)+'&open_modal=1';
    var g=geo[item.peer]||{};link.title=['Origem identificada; não confirma ataque',g.country,g.region,g.isp].filter(function(x){return typeof x==='string'&&x;}).join(' — ');row.appendChild(link);
   }
   var code=document.createElement('code');code.textContent=item.text;row.appendChild(code);fragment.appendChild(row);
  });
  if(!shown){var empty=document.createElement('div');empty.textContent=cache.length?'Nenhuma linha desta amostra corresponde ao filtro.':'Nenhuma linha completa exibida; confira o estado e os avisos.';fragment.appendChild(empty);}
  out.replaceChildren(fragment);count.textContent=shown+' exibida(s) de '+cache.length+' linha(s) recebida(s).';if(stick)out.scrollTop=out.scrollHeight;
 }
 function load(force){
  if(analyzing||document.hidden||(!force&&paused))return;
  if(!available()){status.textContent='Nenhum arquivo legível disponível no catálogo.';buttons();return;}
  if(busy){if(force)pending=true;return;}
  clearTimeout(timer);busy=true;buttons();var mine=generation,selected=path.value,lines=limit.value;status.textContent='Consultando; os dados anteriores ainda não estão confirmados nesta atualização.';
  request('fetch_lines',{path:selected,lines:lines},true,15000).then(function(data){
   if(mine!==generation||selected!==path.value||lines!==limit.value)return;
   if(!data.success)throw new Error(data.error||'Leitura indisponível.');
   if(data.path!==selected||!Array.isArray(data.lines)||data.lines.length>1000||data.total!==data.lines.length||!Array.isArray(data.warnings)||!data.warnings.every(function(w){return typeof w==='string';})||typeof data.observed_at!=='string'||data.lines.some(function(x){return !x||typeof x.text!=='string'||['normal','error','suspicious'].indexOf(x.class)<0;}))throw new Error('Contrato de leitura inválido.');
   cache=data.lines;geo=data.geo_data&&typeof data.geo_data==='object'?data.geo_data:{};warnings.textContent=data.warnings.join(' ');render();failures=0;
   status.textContent=(data.empty_file?'Arquivo vazio confirmado. ':'Leitura concluída. ')+data.observed_at+(paused?' — atualização automática pausada.':'');
  }).catch(function(error){if(mine!==generation)return;failures++;status.textContent='Leitura não confirmada; dados anteriores podem estar desatualizados. '+(error.message||'Falha de conexão.');})
  .finally(function(){busy=false;active=null;buttons();if(pending){pending=false;load(true);}else schedule();});
 }
 function changed(){generation++;cache=[];geo={};warnings.textContent='';render();if(active)active.abort();load(true);buttons();}
 path.addEventListener('change',changed);limit.addEventListener('change',changed);filter.addEventListener('input',render);
 refresh.addEventListener('click',function(){load(true);});
 pause.addEventListener('click',function(){paused=!paused;pause.textContent=paused?'Retomar atualização':'Pausar atualização';pause.setAttribute('aria-pressed',String(paused));clearTimeout(timer);status.textContent=paused?'Atualização visual pausada; Fail2Ban e IA continuam independentes.':'Retomando atualização.';if(paused){generation++;pending=false;if(active)active.abort();}else load(true);});
 document.addEventListener('visibilitychange',function(){clearTimeout(timer);generation++;pending=false;if(active)active.abort();if(document.hidden)status.textContent='Atualização suspensa enquanto a aba está oculta.';else if(!paused)load(true);});
 analyze.addEventListener('click',function(){
  if(analyze.disabled||analyzing||busy)return;
  var selected=path.value;
  if(!window.confirm('Solicitar análise manual de '+selected+'? Pode consumir tokens e salvar sugestões. Usa até '+root.dataset.analysisLines+' linhas configuradas, não o filtro visual. Não bloqueia IPs imediatamente.'))return;
  var nonce=root.dataset.analysisToken;root.dataset.analysisToken='';analyzing=true;clearTimeout(timer);buttons();result.textContent='Análise manual solicitada. Aguarde; não repita o pedido.';
  request('analyze',{path:selected,lines:limit.value,confirm:'1',analysis_token:nonce},false,120000).then(function(data){
   if(typeof data.analysis_token==='string')root.dataset.analysisToken=data.analysis_token;
   result.textContent=selected+': '+(data.message||data.error||(data.success?'Análise concluída.':'Resultado não confirmado.'))+(!root.dataset.analysisToken?' Atualize a página antes de outra solicitação.':'');
  }).catch(function(){result.textContent='Resultado não confirmado. A análise pode ter iniciado; confira a aba IA antes de repetir. Atualize a página para nova confirmação.';})
  .finally(function(){analyzing=false;buttons();schedule();});
 });
 window.addEventListener('pagehide',function(){clearTimeout(timer);generation++;pending=false;if(active)active.abort();});
 window.addEventListener('pageshow',function(event){if(event.persisted&&!paused)load(true);});
 buttons();load(true);
});
})();
