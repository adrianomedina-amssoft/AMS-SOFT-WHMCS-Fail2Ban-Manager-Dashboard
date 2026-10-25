'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(__dirname+'/../assets/js/logviewer.js','utf8');let checks=0;
function ok(v,m){assert(v,m);checks++;}
function node(){return {value:'',textContent:'',dataset:{},children:[],disabled:false,handlers:{},scrollTop:0,scrollHeight:100,clientHeight:100,
 addEventListener(e,f){this.handlers[e]=f;},appendChild(c){this.children.push(c);},replaceChildren(c){this.children=c.children||[c];},setAttribute(k,v){this[k]=v;},
 set innerHTML(v){throw new Error('Unsafe HTML insertion');}};}
function flatten(n){return n.textContent+n.children.map(flatten).join('');}
function start(){
 const nodes={},events={},wevents={},timers=new Map(),requests=[];let seq=0,live=0,maxLive=0,confirmed=true;
 ['path','lines','filter','output','status','count','warnings','analysis-result','refresh','pause','analyze'].forEach(id=>nodes[id]=node());
 const root=node();root.dataset={moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'csrf',analysisToken:'nonce',analysisLines:'200'};
 nodes.path.value='/var/log/a.log';nodes.path.selectedOptions=[{disabled:false,dataset:{analyze:'1'}}];nodes.lines.value='100';
 const document={hidden:false,addEventListener:(e,f)=>{events[e]=f;},getElementById:id=>id==='amsfb-viewer'?root:nodes[id.replace('viewer-','')],createElement:node,createDocumentFragment:node};
 const context={document,URLSearchParams,window:{AMSFB:{csrfToken:'csrf'},confirm:()=>confirmed,addEventListener:(e,f)=>{wevents[e]=f;}},
 setTimeout:(f,ms)=>{timers.set(++seq,{f,ms});return seq;},clearTimeout:id=>timers.delete(id),
 AbortController:class{constructor(){this.signal={aborted:false,listeners:[]};}abort(){this.signal.aborted=true;this.signal.listeners.forEach(f=>f());}},
 fetch:(url,args)=>new Promise((resolve,reject)=>{live++;maxLive=Math.max(live,maxLive);const request={url,args,done:false};requests.push(request);
  request.resolve=(data,http=true)=>{if(request.done)return;request.done=true;live--;resolve({ok:http,json:async()=>data});};request.reject=()=>{if(request.done)return;request.done=true;live--;reject(new Error('abort'));};args.signal.listeners.push(request.reject);if(args.signal.aborted)request.reject();})};
 vm.runInNewContext(source,context);events.DOMContentLoaded();
 return {nodes,root,document,events,wevents,timers,requests,context,confirm:v=>{confirmed=v;},max:()=>maxLive,
  respond(data,http=true){const r=requests.find(x=>!x.done);assert(r,'Pending request');r.resolve(data,http);},
  tick(ms){const x=[...timers].find(x=>x[1].ms===ms);assert(x,'Timer '+ms);timers.delete(x[0]);x[1].f();}};
}
const flush=async()=>{for(let i=0;i<12;i++)await new Promise(resolve=>setImmediate(resolve));};
const sample=(path='/var/log/a.log')=>({success:true,path,lines:[{text:'<img src=x onerror=bad> 192.0.2.1',class:'suspicious',peer:'192.0.2.1'}],total:1,warnings:[],observed_at:'now',empty_file:false,geo_data:{}});
async function loaded(){const s=start();s.respond(sample());await flush();return s;}
(async()=>{
 let s=start();ok(s.requests.length===1,'One initial read');s.nodes.refresh.handlers.click();s.nodes.refresh.handlers.click();ok(s.requests.length===1,'No overlapping read');s.respond(sample());await flush();ok(s.requests.length===2&&s.max()===1,'One queued manual refresh');s.respond(sample());await flush();
 ok(flatten(s.nodes.output).includes('<img')&&s.nodes.output.children[0].children[1].textContent.startsWith('<img'),'Log rendered as text');
 const link=s.nodes.output.children[0].children[0];ok(link.href.includes('action=ips&ban_ip=192.0.2.1')&&!link.href.includes('ban_ip&do='),'Review navigation, not ban');
 const before=s.requests.length;s.nodes.filter.value='missing';s.nodes.filter.handlers.input();ok(s.requests.length===before&&s.nodes.count.textContent.startsWith('0 exibida'),'Filter local');
 s.nodes.pause.handlers.click();ok(s.nodes.pause['aria-pressed']==='true','Accessible paused state');s.nodes.refresh.handlers.click();ok(s.requests.length===before+1,'Manual refresh works paused');s.respond(sample());await flush();ok(![...s.timers.values()].some(x=>x.ms===5000),'Paused stops polling');
 s=start();s.nodes.path.value='/var/log/b.log';s.nodes.path.handlers.change();await flush();ok(s.requests[0].done&&s.requests.length===2&&s.max()===1,'Switch aborts old read and queues new');s.respond(sample('/var/log/b.log'));await flush();ok(s.nodes.status.textContent.includes('concluída'),'New selection shown');
 s=start();s.respond({success:false,error:'CSRF',csrf_token:'new'});await flush();ok(s.requests.length===2&&new URLSearchParams(s.requests[1].args.body).get('csrf_token')==='new','Read CSRF retry');s.respond({success:false,error:'CSRF'});await flush();ok(s.requests.length===2,'Only one CSRF retry');
 for(const response of [{data:{},http:true},{data:sample(),http:false},{data:{...sample(),path:'/var/log/wrong.log'},http:true},{data:{...sample(),lines:[{text:'x',class:'evil'}]},http:true}]){s=start();s.respond(response.data,response.http);await flush();ok(s.nodes.status.textContent.includes('não confirmada')&&s.requests.length===1,'HTTP/JSON/contract failure not success');}
 s=start();s.tick(15000);await flush();ok(s.nodes.status.textContent.includes('não confirmada')&&s.requests[0].done,'Read timeout');
 s=await loaded();s.document.hidden=true;s.events.visibilitychange();ok(s.timers.size===0,'Hidden stops timer');s.nodes.refresh.handlers.click();ok(s.requests.length===1,'Hidden manual read suppressed');s.document.hidden=false;s.events.visibilitychange();ok(s.requests.length===2,'Visible resumes');
 s=await loaded();s.confirm(false);s.nodes.analyze.handlers.click();ok(s.requests.length===1,'Analysis cancellation');s.confirm(true);s.nodes.analyze.handlers.click();s.nodes.analyze.handlers.click();ok(s.requests.length===2&&s.root.dataset.analysisToken===''&&s.nodes.analyze.disabled,'One confirmed analysis, consume local token');
 const body=new URLSearchParams(s.requests[1].args.body);ok(body.get('confirm')==='1'&&body.get('analysis_token')==='nonce','Explicit confirmation payload');
 s.respond({success:false,error:'CSRF',csrf_token:'rotated'});await flush();ok(s.requests.length===2&&s.nodes.analyze.disabled,'Analysis never retries CSRF');
 s=await loaded();s.nodes.analyze.handlers.click();s.respond({success:true,message:'done',analysis_token:'next'});await flush();ok(s.root.dataset.analysisToken==='next'&&!s.nodes.analyze.disabled,'New confirmation only after response');
 s=await loaded();s.nodes.analyze.handlers.click();s.tick(120000);await flush();ok(s.nodes['analysis-result'].textContent.includes('pode ter iniciado')&&s.nodes.analyze.disabled,'Uncertain analysis not repeatable');
 s=await loaded();s.nodes.path.selectedOptions[0].dataset.analyze='0';s.nodes.path.handlers.change();await flush();ok(s.nodes.analyze.disabled,'Operational log analysis disabled');
 s=await loaded();s.wevents.pagehide();ok(s.timers.size===0,'Page departure stops timers');
 ok(!source.includes('innerHTML')&&!source.includes("request('ban"),'No HTML injection or inline ban mutation');
 console.log('PASS: '+checks+' log viewer polling/stale/filter/CSRF/analysis/UI checks; offline DOM');
})().catch(e=>{console.error(e);process.exit(1);});
