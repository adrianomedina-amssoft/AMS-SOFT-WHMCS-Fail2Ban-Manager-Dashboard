(function () {
    'use strict';
    document.addEventListener('DOMContentLoaded', function () {
        var root=document.getElementById('amsfb-logpaths');
        if(!root)return;
        var button=document.getElementById('amsfb-validate-new'), input=document.getElementById('amsfb-new-path'), result=document.getElementById('amsfb-new-val-result');
        var generation=0, validating=false, submitting=false;
        function notice(text, good){result.textContent=text;result.className=good?'text-success':'text-warning';}
        function token(){return (window.AMSFB&&window.AMSFB.csrfToken)||root.dataset.csrf||'';}
        function sync(value){
            if(typeof value!=='string'||!value)return;
            root.dataset.csrf=value;if(window.AMSFB)window.AMSFB.csrfToken=value;
            root.querySelectorAll('input[name="csrf_token"]').forEach(function(el){el.value=value;});
        }
        input.addEventListener('input',function(){generation++;notice('Caminho alterado; valide novamente.',false);});
        button.addEventListener('click',function(){
            if(validating||submitting||!input.value.trim())return;
            var path=input.value, current=++generation;
            validating=true;button.disabled=true;notice('Verificando metadados...',false);
            var controller=new AbortController(), timer=setTimeout(function(){controller.abort();},15000);
            function send(retried){
                return fetch(root.dataset.moduleLink+'&action=logpaths&do=validate',{
                    method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'XMLHttpRequest'},
                    body:new URLSearchParams({csrf_token:token(),path:path}).toString(),signal:controller.signal
                }).then(function(response){if(!response.ok)throw new Error('HTTP');return response.json();})
                .then(function(data){
                    if(!data||typeof data.success!=='boolean')throw new Error('JSON');
                    sync(data.csrf_token);
                    if(current!==generation||input.value!==path)return;
                    if(!data.success&&typeof data.error==='string'&&/CSRF/i.test(data.error)&&!retried)return send(true);
                    if(!data.success){notice(data.error||'Validação não concluída.',false);return;}
                    if(typeof data.valid!=='boolean'||typeof data.readable!=='boolean'||typeof data.message!=='string')throw new Error('Contract');
                    notice(data.message,data.valid&&data.readable);
                });
            }
            send(false).catch(function(){if(current===generation&&input.value===path)notice('Consulta não concluída. Verifique a conexão e valide novamente.',false);})
            .finally(function(){clearTimeout(timer);validating=false;button.disabled=false;});
        });
        root.querySelectorAll('form').forEach(function(form){form.addEventListener('submit',function(event){
            if(submitting||validating){event.preventDefault();return;}
            if(form.classList.contains('amsfb-logpath-delete')&&!window.confirm('Remover somente o cadastro exibido? Arquivo, jails, histórico e fontes da IA permanecem.')){event.preventDefault();return;}
            sync(token());submitting=true;
        });});
        window.addEventListener('pageshow',function(){submitting=false;});
    });
})();
