// Offline DOM/event fixtures. fetch never performs network I/O.
'use strict';
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
let checks = 0;
function check(value, message) { assert.ok(value, message); checks++; }
function node(id) {
    return {id, value:'', checked:true, disabled:false, hidden:false, dataset:{}, listeners:{}, attrs:{},
        classList:{toggle(){}}, parentElement:{classList:{toggle(){}}},
        addEventListener(name, fn){(this.listeners[name] ||= []).push(fn);},
        emit(name, event={}){(this.listeners[name] || []).forEach(fn => fn(Object.assign({preventDefault(){},stopPropagation(){}}, event)));},
        setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k]??null;},focus(){this.focused=true;},closest(){return null;}};
}
async function fixture() {
    const ids=['amsfb-protection','amsfb-policy','amsfb-defaults','policy-feedback','native_probe_groups','ai_auto_enabled','amsfb-maintenance','maintenance-kind','maintenance-scope','maintenance-preview','maintenance-queue','maintenance-confirm','maintenance-output','maintenance-status','maintenance-preview-summary','maintenance-jails','maintenance-cutoff','maintenance-logs','maintenance-suggestions','maintenance-observations','maintenance-monitor'];
    const elements=Object.fromEntries(ids.map(id=>[id,node(id)]));
    const tabs=[node('tab-0'),node('tab-1')];
    tabs.forEach((tab,i)=>{tab.attrs['aria-controls']='panel-'+i;elements['panel-'+i]=node('panel-'+i);});
    const choices=[node('env'),node('git')];choices.forEach(n=>n.dataset.nativeGroup=n.id);
    const retry=node('retry');retry.dataset.job='fixture-job';const requeue=node('requeue');requeue.dataset.task='fixture-task';
    const root=elements['amsfb-protection'];root.dataset={endpoint:'https://fixture.invalid/protection',csrf:'fixture-token'};root.contains=()=>true;
    root.querySelectorAll=selector=>selector==='[role="tab"]'?tabs:selector==='[data-native-group]'?choices:selector==='.maintenance-retry'?[retry]:selector==='.queue-requeue:not([disabled])'?[requeue]:[];
    elements['amsfb-policy'].querySelectorAll=()=>[elements['native_probe_groups'],elements['ai_auto_enabled']];
    elements['native_probe_groups'].value='env\ngit';elements['native_probe_groups'].dataset.default='env';
    elements['ai_auto_enabled'].value='1';elements['ai_auto_enabled'].dataset.default='0';
    const inputs=['maintenance-kind','maintenance-scope','maintenance-confirm','maintenance-jails','maintenance-cutoff','maintenance-logs','maintenance-suggestions','maintenance-observations','maintenance-monitor'].map(id=>elements[id]);
    const panels={};elements['amsfb-maintenance'].querySelector=selector=>(panels[selector] ||= node(selector));
    elements['amsfb-maintenance'].querySelectorAll=()=>inputs;
    elements['maintenance-kind'].value='monitor';elements['maintenance-scope'].value='ai';
    let clock=1000000;const requests=[];const timers=new Map();let tid=0;
    const context={URLSearchParams,AbortController,Date:{now:()=>clock},Object,Array,Number,JSON,
        window:{location:{hash:''},addEventListener(){}},document:{getElementById:id=>elements[id]||null},
        setTimeout:(fn,ms)=>{timers.set(++tid,{fn,ms});return tid;},clearTimeout:id=>timers.delete(id),
        fetch:(url,args)=>new Promise((resolve,reject)=>requests.push({url,args,resolve,reject}))};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../assets/js/protection.js'),'utf8'),context);
    const flush=()=>new Promise(resolve=>setImmediate(resolve));
    const reply=async(index,body)=>{requests[index].resolve({ok:true,json:()=>Promise.resolve(body)});await flush();};
    return {elements,tabs,choices,retry,requeue,requests,reply,flush,panels,timers,advance:ms=>{clock+=ms;}};
}
(async()=>{
    const f=await fixture(),e=f.elements;
    check(e['maintenance-queue'].disabled,'Confirmation initially gated');
    check(f.panels['[data-archive-controls]'].hidden,'Monitor does not show cleanup controls');
    e['maintenance-preview'].emit('click');
    let payload=new URLSearchParams(f.requests[0].args.body);
    check(payload.get('clear_logs')==='0'&&payload.get('clear_observations')==='0','Monitor does not freeze deletion candidates');
    e['maintenance-kind'].value='unban';e['maintenance-kind'].emit('change');
    e['maintenance-scope'].value='all';e['maintenance-scope'].emit('change');
    await f.reply(0,{success:true,nonce:'obsolete',expires_in:300});
    check(e['maintenance-queue'].disabled&&e['maintenance-preview-summary'].hidden,'Late response cannot revive invalid preview');
    e['maintenance-preview'].emit('click');e['maintenance-preview'].emit('click');
    await f.reply(2,{success:true,nonce:'newest',expires_in:300,bans:2,records:{},monitor_hours:0});
    await f.reply(1,{success:true,nonce:'older',expires_in:300});
    e['maintenance-confirm'].value='EXECUTAR MANUTENCAO';e['maintenance-confirm'].emit('input');
    check(!e['maintenance-queue'].disabled,'Newest valid preview and exact phrase enable confirmation');
    check(e['maintenance-preview-summary'].textContent.includes('todas as jails'),'Frozen scope summarized');
    e['maintenance-queue'].emit('click');payload=new URLSearchParams(f.requests[3].args.body);
    check(payload.get('nonce')==='newest','Out-of-order response never replaces nonce');
    check(e['maintenance-kind'].disabled,'Scope cannot change during confirmation request');
    await f.reply(3,{success:false,error:'Fixture refusal'});
    check(!e['maintenance-queue'].disabled&&!e['maintenance-kind'].disabled,'Valid preview survives corrected refusal');
    e['maintenance-queue'].emit('click');await f.reply(4,{success:true,job:'fixture',status:'queued'});
    check(e['maintenance-queue'].disabled,'Successful queue cannot be accidentally submitted again');
    check(e['maintenance-status'].textContent.includes('depende do cron'),'Queued is not falsely reported as completed');
    e['maintenance-preview'].emit('click');await f.reply(5,{success:true,nonce:'expires',expires_in:300});f.advance(300001);e['maintenance-confirm'].emit('input');
    check(e['maintenance-queue'].disabled,'Expired preview gated without waiting on timer');
    e['maintenance-preview'].emit('click');f.requests[6].reject(new Error('network'));await f.flush();
    check(e['maintenance-queue'].disabled&&e['maintenance-status'].textContent.includes('Falha de comunicação'),'Network error never authorizes queue');
    e['maintenance-confirm'].value='wrong';const count=f.requests.length;f.retry.emit('click');
    check(f.requests.length===count&&e['maintenance-confirm'].focused,'Retry requires explicit phrase');
    e['amsfb-defaults'].emit('click');
    check(e['ai_auto_enabled'].value==='0'&&f.choices[0].checked&&!f.choices[1].checked,'Defaults synchronize native choices without saving');
    check(f.requests.length===count,'Defaults have no HTTP side effect');
    f.tabs[0].emit('keydown',{key:'ArrowRight'});
    check(f.tabs[1].attrs['aria-selected']==='true'&&!e['panel-1'].hidden&&f.tabs[1].focused,'Arrow key selects/focuses linked panel');
    f.tabs[1].emit('keydown',{key:'Home'});
    check(f.tabs[0].attrs['aria-selected']==='true'&&e['panel-1'].hidden,'Home key restores first tab');
    const delayed=await fixture(),de=delayed.elements;
    de['maintenance-preview'].emit('click');delayed.advance(40000);
    await delayed.reply(0,{success:true,nonce:'delayed',expires_in:300});
    de['maintenance-confirm'].value='EXECUTAR MANUTENCAO';de['maintenance-confirm'].emit('input');
    check(!de['maintenance-queue'].disabled,'Delayed but unexpired preview still usable');
    delayed.advance(261000);de['maintenance-confirm'].emit('input');
    check(de['maintenance-queue'].disabled,'Response delay cannot extend the server preview deadline');
    const expired=await fixture(),xe=expired.elements;
    xe['maintenance-preview'].emit('click');expired.advance(300001);
    await expired.reply(0,{success:true,nonce:'already-expired',expires_in:300});
    xe['maintenance-confirm'].value='EXECUTAR MANUTENCAO';xe['maintenance-confirm'].emit('input');
    check(xe['maintenance-queue'].disabled&&xe['maintenance-preview-summary'].hidden,'Expired-at-receipt response is never usable');
    const consent=await fixture(),ce=consent.elements;
    ce['maintenance-preview'].emit('click');await consent.reply(0,{success:true,nonce:'monitor',expires_in:300});
    ce['maintenance-confirm'].value='EXECUTAR MANUTENCAO';ce['maintenance-confirm'].emit('input');
    ce['maintenance-kind'].value='both';ce['maintenance-kind'].emit('change');
    check(ce['maintenance-confirm'].value===''&&ce['maintenance-queue'].disabled,'Changed operation must discard prior consent');
    ce['maintenance-preview'].emit('click');await consent.reply(1,{success:true,nonce:'destructive',expires_in:300});
    check(ce['maintenance-queue'].disabled,'New destructive preview cannot inherit monitor consent');
    ce['maintenance-confirm'].value='EXECUTAR MANUTENCAO';ce['maintenance-confirm'].emit('input');
    check(!ce['maintenance-queue'].disabled,'Fresh explicit consent permits frozen operation');
    ce['maintenance-preview'].emit('click');await consent.reply(2,{success:true,nonce:'refreshed',expires_in:300});
    check(ce['maintenance-confirm'].value===''&&ce['maintenance-queue'].disabled,'Refreshed preview requires fresh consent');
    ce['maintenance-preview'].emit('click');
    ce['maintenance-confirm'].value='EXECUTAR MANUTENCAO';ce['maintenance-confirm'].emit('input');
    await consent.reply(3,{success:true,nonce:'late-selection',expires_in:300});
    check(ce['maintenance-confirm'].value===''&&ce['maintenance-queue'].disabled,'Consent typed before targets arrive cannot authorize them');
    console.log('PASS: '+checks+' offline maintenance race/expiry/confirmation/defaults/keyboard checks; no HTTP/SQL/provider');
})().catch(error=>{console.error(error);process.exitCode=1;});
