'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(__dirname+'/../assets/js/ips.js','utf8');
let checks=0;function ok(v,message){assert(v,message);checks++;}
async function scenario(responses,confirmValue=true){
 let ready,click,submit,reloads=0,requests=[];const notices={focus(){},textContent:'',hidden:true};
 const button={dataset:{ip:'198.51.100.1',jail:'a',preview:'signed-ticket'},disabled:false,addEventListener:(ev,fn)=>{click=fn;}};
 const root={dataset:{moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'old',openModal:'0'},querySelectorAll:()=>[button]};
 const form={addEventListener:(ev,fn)=>{submit=fn;}};
 const context={URLSearchParams,window:{AMSFB:{csrfToken:'old'},location:{reload(){reloads++;}}},confirm:()=>confirmValue,
  document:{addEventListener:(ev,fn)=>{ready=fn;},getElementById:id=>({'amsfb-ips-view':root,'amsfb-ips-notice':notices,'amsfb-ips-ban-form':form}[id]||null)},
  fetch:async(url,options)=>{requests.push({url,options});const r=responses.shift();if(r instanceof Error)throw r;return {ok:r.http!==false,status:r.status||200,json:async()=>r.data};}};
 vm.runInNewContext(source,context);ok(requests.length===0,'No request on load');ready();click();click();
 for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));
 return {requests,reloads,notices,button,context,submit};
}
(async()=>{
 let r=await scenario([{data:{success:true,message:'ticket removed'}}]);ok(r.requests.length===1&&r.reloads===1,'Single operation and full refresh');
 let body=new URLSearchParams(r.requests[0].options.body);ok(body.get('preview')==='signed-ticket'&&body.get('jail')==='a','Signed selected ticket sent');
 ok(r.requests[0].options.method==='POST','Mutation POST only');
 r=await scenario([{data:{success:false,error:'Invalid CSRF token',csrf_token:'new'}},{data:{success:true}}]);ok(r.requests.length===2&&r.reloads===1,'One CSRF retry');
 ok(new URLSearchParams(r.requests[1].options.body).get('csrf_token')==='new','Retry uses returned token');
 r=await scenario([{data:{success:false,error:'CSRF'}},{data:{success:false,error:'CSRF'}}]);ok(r.requests.length===2&&r.reloads===0&&!r.button.disabled,'No infinite CSRF retry');
 r=await scenario([{http:false,status:500}]);ok(r.requests.length===1&&r.reloads===0&&r.notices.textContent.includes('pode ter sido aplicada'),'HTTP failure not retried or assumed unapplied');
 r=await scenario([new Error('network')]);ok(r.requests.length===1&&r.reloads===0,'Network failure no retry');
 r=await scenario([{data:{success:'true'}}]);ok(r.reloads===0,'Malformed success refused');
 r=await scenario([{data:{success:false,error:'<img src=x onerror=alert(1)>'}}]);ok(r.notices.textContent==='<img src=x onerror=alert(1)>'&&r.notices.innerHTML===undefined,'Response inserted as text only');
 r=await scenario([],false);ok(r.requests.length===0,'Cancel does not mutate');
 r=await scenario([{data:{success:true,warning:true,message:'Audit failed'}}]);ok(r.reloads===1&&r.notices.className.includes('warning'),'Confirmed result with audit warning refreshes');
 ok(!source.includes('row.remove('),'No stale local row removal');
 console.log('PASS: '+checks+' IP AJAX/CSRF/HTTP/concurrency/confirmation/text checks; offline DOM');
})().catch(e=>{console.error(e);process.exit(1);});
