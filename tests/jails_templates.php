<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\JailAdmin as A;
$checks=0;function t42($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
function render42($template,$data){
    extract(array_merge(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban','csrf_token'=>'token','asset_base'=>'/assets',
        'filters'=>['sshd'],'prefill'=>['new_jail'=>'','filter'=>'','logpath'=>'','maxretry'=>'5','findtime'=>'600','bantime'=>'-1'],
        'e'=>fn($v)=>htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8')],$data));
    ob_start();include dirname(__DIR__).'/templates/'.$template.'.tpl';return ob_get_clean();
}
set_error_handler(function($n,$s){throw new RuntimeException($s);});
$state=['effective'=>['a'=>['enabled'=>'true','findtime'=>'10m','bantime'=>'48h','maxretry'=>'1','logpath'=>"/var/log/a\n/var/log/b",'filter'=>'<script>attack</script>']],
    'local'=>['a'=>['enabled'=>'true']],'digest'=>'fixture'];
$view=['selection'=>A::select($state,['a'],[]),'snapshot'=>$state,'names'=>['a'],'at'=>1000,'errors'=>[],'previews'=>['a'=>'signature'],'add_preview'=>'add','statuses'=>['a'=>['currently_banned'=>3,'total_banned'=>4,'currently_failed'=>2,'total_failed'=>9]]];
$html=render42('jails_overview',['view'=>$view]);
t42(str_contains($html,'data-jail-counts')&&str_contains($html,'Configuradas:'),'Explicit count domains');
t42(str_contains($html,'findtime: 10m')&&str_contains($html,'bantime: 48h')&&!str_contains($html,'48hs'),'No appended seconds to native units');
t42(!str_contains($html,'<script>attack</script>')&&str_contains($html,'&lt;script&gt;attack'),'Config XSS escaped');
t42(str_contains($html,'Remover seção local')&&str_contains($html,'reativá-la'),'Local-only removal and inheritance warning');
t42(str_contains($html,'data-preview="signature"')&&str_contains($html,'value="add"'),'Signed tokens in actions and creation');
t42(str_contains($html,'value="-1"')&&!str_contains($html,'name="bantime" min="60"'),'Permanent ban can be entered');
$view['snapshot']=null;$view['previews']=[];$view['add_preview']='';$view['names']=null;$view['selection']['loaded']=null;$view['statuses']=['a'=>null];
$html=render42('jails_overview',['view'=>$view]);
t42(str_contains($html,'Não confirmado')&&str_contains($html,'não medido'),'Unknown not zero/offline');
t42(str_contains($html,'<fieldset disabled>')&&str_contains($html,'data-preview="" disabled'),'Unknown prevents mutation');
$html=render42('jail_editor',['snapshot'=>$state,'jail'=>'a','preview'=>'sig','error'=>null]);
t42(str_contains($html,'name="findtime" value="10m"')&&str_contains($html,'name="bantime" value="48h"'),'Editor preserves units');
t42(str_contains($html,"/var/log/a\n/var/log/b</textarea>"),'Multiline visible and preserved');
t42(str_contains($html,'name="confirm" value="1" required'),'Explicit impact acknowledgement');
$state['effective']['a']['logpath']='</textarea><script>attack</script>';
$html=render42('jail_editor',['snapshot'=>$state,'jail'=>'a','preview'=>'sig','error'=>null]);
t42(!str_contains($html,'</textarea><script>attack')&&str_contains($html,'&lt;/textarea&gt;'),'Textarea breakout escaped');
$html=render42('jail_editor',['snapshot'=>null,'jail'=>'','preview'=>'','error'=>'Indisponível']);
t42(!str_contains($html,'type="submit"')&&str_contains($html,'Indisponível'),'Unknown editor cannot submit defaults');
restore_error_handler();
echo "PASS: {$checks} jails templates/units/XSS/unknown-state checks; pure render\n";
