'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const template=fs.readFileSync(__dirname+'/../templates/dashboard_overview.tpl','utf8');
let script=template.match(/<script>([\s\S]*?)<\/script>/)[1];
const days=[{date:'2026-10-24',count:0},{date:'2026-10-23',count:2}],top=[{ip:'198.51.100.1',count:'3'}];
script=script.replace(/<\?= \$json\(\$history\['days'\]\?\?\[\]\) \?>/,JSON.stringify(days))
 .replace(/<\?= \$json\(\$history\['top'\]\?\?\[\]\) \?>/,JSON.stringify(top));
let checks=0;function check(x,message){assert(x,message);checks++;}
function run(chart=true,canvases=true){
 const calls=[],events=[];let ready;
 const context={document:{addEventListener:(event,fn)=>{events.push(event);ready=fn;},getElementById:id=>canvases?{id}:null}};
 if(chart)context.Chart=function(node,config){calls.push({id:node.id,config});};
 vm.runInNewContext(script,context);check(calls.length===0,'No render before DOM ready');
 check(events[0]==='DOMContentLoaded','Initialization waits for local Chart script');ready();return calls;
}
const calls=run();check(calls.length===2,'Two charts');
check(calls[0].config.data.datasets[0].data[0]===0,'Zero preserved');
check(calls[1].config.data.datasets[0].data[0]===3,'SQL numeric string converted');
check(calls[1].config.options.indexAxis==='y','Horizontal IP chart');
check(calls[0].config.data.datasets[0].label.includes('módulo'),'Scope in legend');
check(run(false).length===0,'No Chart dependency: textual fallback remains');
check(run(true,false).length===0,'Missing/unknown datasets: no canvas errors');
check(template.includes('<summary>Ver valores por dia</summary>')&&template.includes('<summary>Ver IPs e contagens</summary>'),'Text alternatives');
check(!script.includes('fetch('),'Dashboard charts do not trigger requests');
console.log('PASS: '+checks+' dashboard chart/loading/fallback checks; offline DOM');
