'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(__dirname+'/../assets/js/jails.js','utf8');
let checks=0;function ok(v,message){assert(v,message);checks++;}
async function scenario(responses,confirmValue=true,operation='disable',clickFirst=true){
 let ready,click,submit,reloads=0,requests=[],confirmation='';const notices={focus(){},textContent:'',hidden:true};
 const input={value:'old'};
 const button={dataset:{jail:'a',do:operation,preview:'signed-config'},disabled:false,addEventListener:(ev,fn)=>{click=fn;}};
 const form={addEventListener:(ev,fn)=>{submit=fn;},querySelector:()=>input};
 const root={dataset:{moduleLink:'addonmodules.php?module=amssoft_fail2ban',csrf:'old'},querySelectorAll:selector=>selector==='.amsfb-jail-action'?[button]:[form]};
 const context={URLSearchParams,window:{AMSFB:{csrfToken:'old'},location:{reload(){reloads++;}}},confirm:message=>{confirmation=message;return confirmValue;},
  document:{addEventListener:(ev,fn)=>{ready=fn;},getElementById:id=>({'amsfb-jails-view':root,'amsfb-jails-notice':notices}[id]||null)},
  fetch:async(url,options)=>{requests.push({url,options});const r=responses.shift();if(r instanceof Error)throw r;return {ok:r.http!==false,status:r.status||200,json:async()=>r.data};}};
 vm.runInNewContext(source,context);ready();ok(requests.length===0,'GET UI makes no native mutation request');
 if(clickFirst){click();click();}
 for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));
 return {requests,reloads,notices,button,context,submit,input,confirmation,click};
}
(async()=>{
 let r=await scenario([{data:{success:true}}]);ok(r.requests.length===1&&r.reloads===1,'Single request and full refresh');
 let body=new URLSearchParams(r.requests[0].options.body);ok(body.get('preview')==='signed-config'&&body.get('confirm')==='1','Signed config plus impact confirmation');
 ok(r.requests[0].options.method==='POST'&&body.get('do')==='disable','POST operation');
 ok(r.confirmation.includes('liberar'),'Disable impact shown');
 r=await scenario([{data:{success:true}}],true,'remove');ok(r.confirmation.includes('reativar')&&r.reloads===1,'Removal warns about inherited activation then refreshes');
 r=await scenario([{data:{success:false,error:'Invalid CSRF token',csrf_token:'new'}},{data:{success:true}}]);ok(r.requests.length===2&&r.reloads===1,'One explicit CSRF retry');
 ok(new URLSearchParams(r.requests[1].options.body).get('csrf_token')==='new','New CSRF used');
 r=await scenario([{data:{success:false,error:'CSRF'}},{data:{success:false,error:'CSRF'}}]);ok(r.requests.length===2&&r.reloads===0&&r.button.disabled,'Bounded retry and locked controls');
 r=await scenario([{http:false,status:500}]);ok(r.requests.length===1&&r.reloads===0&&r.notices.textContent.includes('pode ter sido aplicada'),'HTTP failure not replayed');
 r.click();ok(r.requests.length===1,'No second click after unknown outcome');
 r=await scenario([new Error('network')]);ok(r.requests.length===1&&r.reloads===0,'No fallback form replay');
 r=await scenario([{data:{success:'true'}}]);ok(r.reloads===0&&r.button.disabled,'Malformed response never successful');
 r=await scenario([{data:{success:false,error:'<img src=x onerror=alert(1)>'}}]);ok(r.notices.textContent==='<img src=x onerror=alert(1)>'&&r.notices.innerHTML===undefined,'Safe text rendering');
 r=await scenario([],false);ok(r.requests.length===0,'Cancel no command');
 r=await scenario([{data:{success:true,warning:true}}]);ok(r.reloads===1,'Audit warning preserved by server flash on GET');
 r=await scenario([],true,'disable',false);r.context.window.AMSFB.csrfToken='fresh';let prevented=false;r.submit({preventDefault(){prevented=true;}});ok(!prevented&&r.input.value==='fresh','Forms use current CSRF');
 r.submit({preventDefault(){prevented=true;}});ok(prevented,'No duplicate form submit');
 ok(!source.includes('.submit()')&&!source.includes('removeChild')&&!source.includes('innerHTML'),'No auto-replay or stale row deletion');
 console.log('PASS: '+checks+' jails AJAX/CSRF/HTTP/confirmation/form checks; offline DOM');
})().catch(e=>{console.error(e);process.exit(1);});
