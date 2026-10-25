'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(__dirname+'/../assets/js/logpaths.js','utf8');
let checks=0;function ok(v,m){assert(v,m);checks++;}
async function scenario(responses,options={}){
 let ready,click,inputEvent,submitAdd,submitDelete,pageShow,timer,aborted=false,requests=[];
 const inputs=[{value:'old'},{value:'old'},{value:'old'}];
 const result={textContent:'',className:''};const button={disabled:false,addEventListener:(e,f)=>{click=f;}};
 const input={value:'/var/log/a.log',addEventListener:(e,f)=>{inputEvent=f;}};
 const add={classList:{contains:()=>false},addEventListener:(e,f)=>{submitAdd=f;}};
 const del={classList:{contains:()=>true},addEventListener:(e,f)=>{submitDelete=f;}};
 const root={dataset:{moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'old'},querySelectorAll:s=>s==='form'?[add,del]:inputs};
 const context={URLSearchParams,AbortController:class {constructor(){this.signal={};}abort(){aborted=true;}},setTimeout:f=>{timer=f;return 1;},clearTimeout:()=>{},
 window:{AMSFB:{csrfToken:'old'},confirm:()=>options.confirm!==false,addEventListener:(e,f)=>{pageShow=f;}},
 document:{addEventListener:(e,f)=>{ready=f;},getElementById:id=>({'amsfb-logpaths':root,'amsfb-validate-new':button,'amsfb-new-path':input,'amsfb-new-val-result':result}[id])},
 fetch:async(url,request)=>{requests.push({url,request});if(options.edit){input.value='/var/log/b.log';inputEvent();}if(options.timeout)timer();const r=responses.shift();if(r instanceof Error)throw r;return {ok:r.http!==false,json:async()=>r.data};}};
 vm.runInNewContext(source,context);ok(requests.length===0,'No automatic fetch');ready();click();click();
 for(let i=0;i<10;i++)await new Promise(resolve=>setImmediate(resolve));
 return {requests,input,inputEvent,result,button,inputs,context,submitAdd,submitDelete,pageShow,aborted};
}
(async()=>{
 let r=await scenario([{data:{success:true,valid:true,readable:true,message:'Legível',csrf_token:'new'}}]);
 ok(r.requests.length===1&&!r.button.disabled&&r.result.className==='text-success','Single validate request and reenable');
 ok(r.requests[0].request.method==='POST'&&new URLSearchParams(r.requests[0].request.body).get('path')==='/var/log/a.log','POST exact path');
 ok(r.inputs.every(x=>x.value==='new')&&r.context.window.AMSFB.csrfToken==='new','All form tokens synchronized');
 r.input.value='/var/log/edited.log';r.inputEvent();ok(r.result.textContent.includes('alterado'),'Editing clears prior validation');
 r=await scenario([{data:{success:false,error:'Invalid CSRF token',csrf_token:'new'}},{data:{success:true,valid:false,readable:false,message:'Bloqueado'}}]);
 ok(r.requests.length===2&&new URLSearchParams(r.requests[1].request.body).get('csrf_token')==='new','Single read-only CSRF retry');
 ok(r.result.className==='text-warning','Invalid file not green');
 r=await scenario([{data:{success:false,error:'CSRF'}},{data:{success:false,error:'CSRF'}}]);ok(r.requests.length===2,'No infinite retry');
 for(const response of [{http:false},{data:{success:'true'}},{data:{success:true}},new Error('Network')]){
  r=await scenario([response]);ok(r.requests.length===1&&r.result.textContent.includes('não concluída')&&!r.button.disabled,'HTTP/JSON/network failure no retry');
 }
 r=await scenario([{data:{success:true,valid:true,readable:true,message:'old'}}],{edit:true});ok(!r.result.textContent.includes('old'),'Stale response ignored');
 r=await scenario([{data:{success:false,error:'<img src=x onerror=alert(1)>'}}]);ok(r.result.textContent.startsWith('<img')&&r.result.innerHTML===undefined,'Error inserted as text');
 r=await scenario([new Error('aborted')],{timeout:true});ok(r.aborted&&!r.button.disabled,'Bounded request abort');
 let prevented=0;r=await scenario([{data:{success:true,valid:true,readable:true,message:'ok'}}],{confirm:false});r.submitDelete({preventDefault(){prevented++;}});ok(prevented===1,'Delete cancellation');
 r=await scenario([{data:{success:true,valid:true,readable:true,message:'ok'}}]);prevented=0;r.submitAdd({preventDefault(){prevented++;}});r.submitAdd({preventDefault(){prevented++;}});ok(prevented===1,'Duplicate form submit prevented');
 r.pageShow();r.submitAdd({preventDefault(){prevented++;}});ok(prevented===1,'Back-navigation resets submit lock');
 ok(!source.includes('innerHTML')&&!source.includes('&do=delete'),'No HTML injection or AJAX mutations');
 console.log('PASS: '+checks+' log paths HTTP/CSRF/stale/timeout/confirmation/UI checks; offline DOM');
})().catch(e=>{console.error(e);process.exit(1);});
