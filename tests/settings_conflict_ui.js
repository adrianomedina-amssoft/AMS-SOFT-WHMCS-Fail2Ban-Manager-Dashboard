'use strict';
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const source = fs.readFileSync(__dirname + '/../templates/ai_settings.tpl', 'utf8');
const start = source.indexOf('    var saveBtn    =');
const end = source.indexOf('    // Rodar análise agora', start);
assert(start > 0 && end > start);
const script = source.slice(start, end).replace(/<\?= json_encode\(array_keys\(\\AMS\\Fail2Ban\\Policy::fields\(\)\)\) \?>/, '[]');
let checks = 0, posts = [], timers = new Map(), timerId = 0, reloads = 0, accepted = false;
function element() {
    return {disabled:false, value:'', style:{}, children:[], listeners:{},
        addEventListener(name, fn){this.listeners[name]=fn;},
        appendChild(child){this.children.push(child);}};
}
const btn = element(), result = element(), version = element(), prompt = element();
version.value='12'; version.name='policy_version'; prompt.name='ai_prompt'; prompt.value='unsaved text';
const form={querySelectorAll(){return [version,prompt];}};
const nodes={'amsfb-save-btn':btn,'amsfb-settings-result':result,'amsfb-settings-version':version,'amsfb-settings-form':form};
const context={document:{getElementById(id){return nodes[id];},querySelectorAll(){return [];},createElement(){return element();}},
    window:{btoa(s){return Buffer.from(s,'binary').toString('base64');},AMSFB:{post(...args){posts.push(args);}},location:{reload(){reloads++;}}},
    confirm(){return accepted;},setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);}};
vm.runInNewContext(script,context);
function check(value){assert(value);checks++;}
btn.listeners.click();check(posts.length===1&&btn.disabled);
check(!('ai_prompt' in posts[0][2])&&Buffer.from(posts[0][2].ai_prompt_b64,'base64').toString('utf8')===prompt.value);
posts[0][3]({success:true,policy_version:'13',message:'Saved'});
check(version.value==='13'&&!btn.disabled&&timers.size===1);
btn.listeners.click();check(posts.length===2&&timers.size===0);
posts[1][3]({success:false,code:'policy_conflict',reload_required:true,error:'Recarregue'});
check(btn.disabled&&version.value==='13'&&prompt.value==='unsaved text');
check(timers.size===0&&result.style.display==='block'&&result.className==='alert alert-warning');
check(result.children.length===2&&result.children[1].type==='button');
btn.listeners.click();check(posts.length===2);
result.children[1].listeners.click();check(reloads===0&&posts.length===2);
accepted=true;result.children[1].listeners.click();check(reloads===1&&posts.length===2);
check(prompt.value==='unsaved text'&&version.value==='13');
// A different page instance still handles generic errors and success normally.
btn.disabled=false;result.children=[];posts=[];timers.clear();
vm.runInNewContext(script,context);btn.listeners.click();
posts[0][3]({success:false,error:'Generic'});
check(!btn.disabled&&version.value==='13'&&result.className==='alert alert-danger'&&timers.size===1);
for(const fn of timers.values())fn();
check(result.style.display==='none'&&reloads===1);
console.log(`PASS: ${checks} provider settings UI checks; actual embedded script, offline DOM`);
