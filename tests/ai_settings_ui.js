'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),source=fs.readFileSync(__dirname+'/../assets/js/ai_settings.js','utf8');let checks=0;
function ok(v,m){assert(v,m);checks++;}
function node(id){return {id,dataset:{},value:'',disabled:false,textContent:'',handlers:{},addEventListener(e,f){this.handlers[e]=f;},set innerHTML(v){throw Error('Unsafe HTML');}};}
function start(){
 const n={},events={},requests=[],timers=new Map();let seq=0,confirm=true,reloads=0,valid=true;
 ['amsfb-settings','amsfb-settings-form','amsfb-settings-result','amsfb-save-btn','amsfb-settings-reload','amsfb-settings-version','amsfb-ai-prompt','settings-prompt-size','settings-preview-btn','settings-preview','settings-geo-test','settings-geo-clear','settings-model-test','settings-key-test'].forEach(id=>n[id]=node(id));
 const root=n['amsfb-settings'],form=n['amsfb-settings-form'],test=node('test');test.dataset.provider='test';root.dataset={moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'csrf',testToken:'a'.repeat(64)};
 n['amsfb-settings-version'].value='22';n['amsfb-ai-prompt'].value='Análise <HOST> {logs}';n['settings-model-test'].value='model';n['settings-key-test'].value='fixture-key';
 root.querySelectorAll=q=>q==='.settings-test'?[test]:[...Object.values(n),test];form.querySelectorAll=()=>[n['settings-key-test']];form.reportValidity=()=>valid;
 const ctx={document:{getElementById:id=>n[id],addEventListener:(e,f)=>events[e]=f},window:{AMSFB:{csrfToken:'csrf'},confirm:()=>confirm,location:{reload:()=>reloads++},addEventListener:(e,f)=>events[e]=f,btoa:s=>Buffer.from(s,'binary').toString('base64')},URLSearchParams,TextEncoder,unescape,encodeURIComponent,
 FormData:class{forEach(f){Object.entries({csrf_token:'csrf',policy_version:n['amsfb-settings-version'].value,confirm_settings:'1',ai_prompt:n['amsfb-ai-prompt'].value,ai_provider_test_api_key:n['settings-key-test'].value}).forEach(([k,v])=>f(v,k));}},
 setTimeout:(f,ms)=>{timers.set(++seq,{f,ms});return seq;},clearTimeout:id=>timers.delete(id),
 AbortController:class{constructor(){this.signal={listeners:[]};}abort(){this.signal.listeners.forEach(f=>f());}},
 fetch:(url,args)=>new Promise((resolve,reject)=>{const r={url,args,done:false};requests.push(r);r.resolve=(data,http=true)=>{r.done=true;resolve({ok:http,json:async()=>data});};r.reject=()=>{r.done=true;reject(Error('network'));};args.signal.listeners.push(r.reject);})};
 vm.runInNewContext(source,ctx);events.DOMContentLoaded();
 return {n,root,form,test,events,requests,confirm:v=>confirm=v,valid:v=>valid=v,reloads:()=>reloads,
 submit(){form.handlers.submit({preventDefault(){}});},respond(data,http=true){requests.find(r=>!r.done).resolve(data,http);},tick(ms){const [id,t]=[...timers].find(x=>x[1].ms===ms);timers.delete(id);t.f();}};
}
const flush=async()=>{for(let i=0;i<15;i++)await new Promise(r=>setImmediate(r));};
(async()=>{
 let s=start();ok(s.requests.length===0,'Opening makes no calls');ok(s.n['settings-prompt-size'].textContent.startsWith(Buffer.byteLength('Análise <HOST> {logs}')+' '),'UTF8 bytes');
 s.valid(false);s.submit();ok(s.requests.length===0,'Required form validation');s.valid(true);s.confirm(false);s.submit();s.test.handlers.click();ok(s.requests.length===0,'Cost/save cancellation');
 s.confirm(true);s.submit();s.submit();s.test.handlers.click();ok(s.requests.length===1,'Single operation');let body=new URLSearchParams(s.requests[0].args.body);
 ok(!body.has('ai_prompt')&&Buffer.from(body.get('ai_prompt_b64'),'base64').toString()==='Análise <HOST> {logs}','Lossless transport');ok(body.get('confirm_settings')==='1'&&body.get('policy_version')==='22'&&body.get('csrf_token')==='csrf','Version and explicit confirmation');
 s.respond({success:true,policy_version:'23',message:'Saved'});await flush();ok(s.n['settings-key-test'].value===''&&s.n['amsfb-settings-version'].value==='23','Credential cleared after confirmed save');
 s.submit();ok(s.requests.length===1&&s.n['amsfb-save-btn'].disabled,'Success requires fresh read');
 for(const kind of ['http','json','timeout','bad-version']){s=start();s.submit();if(kind==='timeout')s.tick(45000);else s.respond(kind==='bad-version'?{success:true,policy_version:23}:{},kind!=='http');await flush();s.submit();ok(s.requests.length===1&&s.n['settings-key-test'].value==='fixture-key'&&s.n['amsfb-save-btn'].disabled,'Uncertain save retains draft, no retry '+kind);}
 s=start();s.submit();s.respond({success:false,code:'policy_conflict',reload_required:true,error:'Conflict'});await flush();s.submit();ok(s.requests.length===1&&s.n['amsfb-settings-version'].value==='22','Conflict never silently rebases');
 s=start();s.submit();s.respond({success:false,code:'validation_error',error:'Invalid'});await flush();ok(!s.n['amsfb-save-btn'].disabled,'Known validation error allows correction');
 s=start();s.n['amsfb-ai-prompt'].value='é'.repeat(4001);s.submit();ok(s.requests.length===0,'Byte limit, not JS character count');
 s=start();s.test.handlers.click();s.test.handlers.click();body=new URLSearchParams(s.requests[0].args.body);ok(s.requests.length===1&&body.get('test_token')==='a'.repeat(64)&&body.get('confirm_test')==='1'&&!body.has('logs'),'One synthetic test with ticket');
 s.respond({success:true,message:'<img onerror=bad>',test_token:'b'.repeat(64),observed_at:'now'});await flush();ok(s.n['amsfb-settings-result'].textContent.includes('<img')&&s.root.dataset.testToken==='b'.repeat(64),'Result as text and fresh ticket');ok(s.n['amsfb-settings-version'].value==='22'&&s.n['settings-key-test'].value==='fixture-key','Test never saves form');
 s=start();s.test.handlers.click();s.respond({success:false,error:'Used'});await flush();s.test.handlers.click();ok(s.requests.length===1&&!s.root.dataset.testToken,'No reuse without returned ticket');
 s=start();s.test.handlers.click();s.tick(30000);await flush();s.test.handlers.click();ok(s.requests.length===1&&s.n['amsfb-save-btn'].disabled,'Test timeout does not retry');
 s=start();s.n['settings-preview-btn'].handlers.click();body=new URLSearchParams(s.requests[0].args.body);ok(!body.has('ai_prompt')&&!body.has('api_key'),'Preview sends no draft/key');s.respond({success:true,preview:{system:'<HOST> saved'}});await flush();ok(s.n['settings-preview'].textContent==='<HOST> saved'&&!s.n['amsfb-save-btn'].disabled,'Lazy text-only preview');
 s=start();s.form.handlers.input();let prevented=false;s.events.beforeunload({preventDefault(){prevented=true;}});ok(prevented,'Dirty navigation guard');s.confirm(false);s.n['amsfb-settings-reload'].handlers.click();ok(s.reloads()===0,'Cancelled dirty reload');s.confirm(true);s.n['amsfb-settings-reload'].handlers.click();ok(s.reloads()===1,'Explicit dirty reload');
 for(const [id,key] of [['settings-geo-test','confirm_external'],['settings-geo-clear','confirm_clear']]){s=start();s.confirm(false);s.n[id].handlers.click();ok(s.requests.length===0,'Geo cancellation');s.confirm(true);s.n[id].handlers.click();ok(new URLSearchParams(s.requests[0].args.body).get(key)==='1','Geo explicit scope');s.respond({success:true,message:'done'});await flush();}
 ok(!source.includes('innerHTML')&&!source.includes('setInterval'),'No unsafe HTML/background requests');
 console.log('PASS: '+checks+' AI settings UI confirmation/transport/conflict/timeout/preview checks; offline DOM');
})().catch(e=>{console.error(e);process.exit(1);});
