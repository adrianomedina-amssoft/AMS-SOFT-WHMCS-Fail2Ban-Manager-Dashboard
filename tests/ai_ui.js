'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),source=fs.readFileSync(__dirname+'/../assets/js/ai.js','utf8');let checks=0;
function ok(v,m){assert(v,m);checks++;}
function node(id){return {id,dataset:{},disabled:false,checked:false,style:{},textContent:'',handlers:{},addEventListener(e,f){this.handlers[e]=f;},set innerHTML(v){throw Error('Unsafe HTML');}};}
function start(view='actionable',stored=null){
 const n={},events={},requests=[],timers=new Map();let seq=0,confirm=true,reloads=0;
 ['amsfb-ai-result','amsfb-run-now-btn','amsfb-stop-btn','amsfb-ai-refresh','amsfb-bulk-bar','amsfb-bulk-count','amsfb-select-all','amsfb-bulk-clear-btn','amsfb-bulk-approve-btn','amsfb-bulk-reject-btn','amsfb-evidence-content','amsfb-rule-content'].forEach(id=>n[id]=node(id));
 const root=node('root');root.dataset={moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'csrf',view};
 const row=node('row'),approve=node('approve'),reject=node('reject'),filter=node('filter'),country=node('country'),evidence=node('evidence'),rule=node('rule');
 [row,approve,reject,filter].forEach(x=>x.dataset.id='1');country.dataset.countryCode='BR';evidence.dataset.evidence=JSON.stringify(['<script>attack</script>']);rule.dataset.rule='<img onerror=bad>';
 if(view!=='actionable'){row.disabled=approve.disabled=n['amsfb-select-all'].disabled=true;}
 const map={'.amsfb-row-cb':[row],'.amsfb-approve-btn':[approve],'.amsfb-reject-btn':[reject],'.amsfb-create-filter-btn':[filter],'.amsfb-select-country':[country],'.amsfb-evidence-btn':[evidence],'.amsfb-rule-btn':[rule]};
 root.querySelectorAll=q=>q==='button,input[type=checkbox]'?[...Object.values(n),row,approve,reject,filter,country,evidence,rule]:(map[q]||[]);
 let storage=stored?JSON.stringify(stored):null;
 const context={document:{addEventListener:(e,f)=>events[e]=f,getElementById:id=>id==='amsfb-ai-view'?root:n[id]},window:{AMSFB:{csrfToken:'csrf'},confirm:()=>confirm,location:{reload:()=>reloads++}},URLSearchParams,
 sessionStorage:{getItem:()=>storage,setItem:(k,v)=>storage=v,removeItem:()=>storage=null},
 setTimeout:(f,ms)=>{timers.set(++seq,{f,ms});return seq;},clearTimeout:id=>timers.delete(id),
 AbortController:class{constructor(){this.signal={listeners:[]};}abort(){this.signal.listeners.forEach(f=>f());}},
 fetch:(url,args)=>new Promise((resolve,reject)=>{const r={url,args,done:false};requests.push(r);r.resolve=(data,http=true)=>{r.done=true;resolve({ok:http,json:async()=>data});};r.reject=()=>{r.done=true;reject(Error('network'));};args.signal.listeners.push(r.reject);})};
 vm.runInNewContext(source,context);events.DOMContentLoaded();
 return {n,root,row,approve,reject,filter,country,evidence,rule,requests,timers,confirm:v=>confirm=v,reloads:()=>reloads,storage:()=>storage,
 respond(data,http=true){requests.find(r=>!r.done).resolve(data,http);},tick(ms){const [id,t]=[...timers].find(x=>x[1].ms===ms);timers.delete(id);t.f();}};
}
const flush=async()=>{for(let i=0;i<15;i++)await new Promise(r=>setImmediate(r));};
const list={success:true,logs:[{path:'/var/log/a.log',analysis_token:'a'.repeat(64)},{path:'/var/log/b.log',analysis_token:'b'.repeat(64)}],warnings:[]};
(async()=>{
 let s=start();ok(s.requests.length===0,'No requests on opening');s.evidence.handlers.click();s.rule.handlers.click();ok(s.n['amsfb-evidence-content'].textContent.includes('<script>')&&s.n['amsfb-rule-content'].textContent.includes('<img'),'Evidence and rule as text');
 s.confirm(false);s.approve.handlers.click();ok(s.requests.length===0,'Cancelled mutation');s.confirm(true);s.approve.handlers.click();s.approve.handlers.click();ok(s.requests.length===1,'One mutation in flight');
 s.respond({success:true,message:'confirmed'});await flush();ok(s.approve.disabled&&s.n['amsfb-ai-result'].textContent.includes('Atualize'),'Stale controls frozen, full refresh required');
 s.n['amsfb-ai-refresh'].handlers.click();ok(s.reloads()===1,'Explicit full refresh');
 for(const type of ['csrf','http','json','timeout']){s=start();s.approve.handlers.click();if(type==='timeout')s.tick(120000);else s.respond(type==='csrf'?{success:false,error:'CSRF',csrf_token:'new'}:{},type!=='http');await flush();ok(s.requests.length===1&&s.approve.disabled,'No mutation retry '+type);}
 s=start('protected',{at:Date.now(),ids:[1,2]});s.approve.handlers.click();ok(s.requests.length===0&&s.n['amsfb-bulk-bar'].style.display==='none','No protected selection/actions');
 s=start('actionable',{at:Date.now()-900001,ids:[1]});ok(!s.row.checked,'Expired selection not restored');
 s=start('actionable',{at:Date.now()+9999,ids:[1]});ok(!s.row.checked,'Future selection not restored');
 s=start('actionable',{at:Date.now(),ids:[1]});ok(s.row.checked,'Scoped cross-page selection restored');s.n['amsfb-bulk-approve-btn'].handlers.click();ok(JSON.parse(new URLSearchParams(s.requests[0].args.body).get('ids'))[0]===1,'Bulk sends selected IDs');
 s=start();s.country.handlers.click();s.country.handlers.click();ok(s.requests.length===1,'Country read not overlapping');s.respond({success:true,ids:[1,2],limited:false});await flush();ok(s.row.checked&&s.n['amsfb-bulk-count'].textContent.startsWith('2 '),'Country bounded selection after unlocking');
 s=start();s.country.handlers.click();s.respond({success:true,ids:Array.from({length:201},(_,i)=>i+1)});await flush();ok(s.n['amsfb-ai-result'].textContent.includes('não confirmada'),'Oversized country response refused');
 s=start();s.n['amsfb-run-now-btn'].handlers.click();s.n['amsfb-run-now-btn'].handlers.click();ok(s.requests.length===1,'One manual start');
 ok(new URLSearchParams(s.requests[0].args.body).get('confirm')==='1','Explicit cost confirmation');
 s.respond(list);await flush();ok(s.requests.length===2&&s.requests[1].url.endsWith('analyze_log'),'First source only');let body=new URLSearchParams(s.requests[1].args.body);ok(body.get('analysis_token')==='a'.repeat(64)&&body.get('confirm')==='1','Path ticket sent');
 s.respond({success:true,saved:2,suggestions:[{action:'ban'}]});await flush();ok(s.requests.length===3&&new URLSearchParams(s.requests[2].args.body).get('path')==='/var/log/b.log','Sequential next source, no raw row insertion');
 s.respond({success:true,saved:0});await flush();ok(s.requests.length===3&&s.n['amsfb-ai-result'].textContent.includes('salvas: 2')&&s.n['amsfb-run-now-btn'].disabled,'Manual done requires classified refresh');
 s=start();s.n['amsfb-run-now-btn'].handlers.click();s.respond(list);await flush();s.n['amsfb-stop-btn'].handlers.click();s.respond({success:true,saved:0});await flush();ok(s.requests.length===2&&s.n['amsfb-ai-result'].textContent.includes('interrompidas'),'Stop skips next source');
 for(const type of ['csrf','rate','timeout','bad-saved']){s=start();s.n['amsfb-run-now-btn'].handlers.click();s.respond(list);await flush();
  if(type==='timeout')s.tick(120000);else s.respond(type==='bad-saved'?{success:true}:{success:false,error:type});
  await flush();ok(s.requests.length===2&&s.n['amsfb-run-now-btn'].disabled,'No manual retry/next on '+type);
 }
 ok(!source.includes('innerHTML')&&!source.includes('has_new')&&!source.includes('watermark')&&!source.includes('setInterval'),'No unsafe insertion/legacy watermarks/background analysis');
 console.log('PASS: '+checks+' AI UI request/selection/confirmation/stale/stop/timeout checks; offline DOM, no provider');
})().catch(e=>{console.error(e);process.exit(1);});
