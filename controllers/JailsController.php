<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\{Database,Helper,JailAdmin,Router};

class JailsController
{
    public function __construct(private array $vars, private Router $router) {}

    public function handle(string $action): string
    {
        if (($_SERVER['REQUEST_METHOD']??'GET')==='POST') {
            $do=is_string($_POST['do']??null)?$_POST['do']:'';
            $result=JailAdmin::execute($do,$_POST,$this->router->makeJailConfig());
            $this->flash($result);
            Helper::redirect(($this->vars['modulelink']??'').'&action=jails');
            return '';
        }
        $config=$this->router->makeJailConfig();
        if ($action==='jail_edit') {
            $jail=JailAdmin::name($_GET['jail']??null);
            $state=null;$error=null;$preview='';
            try {
                $state=JailAdmin::snapshot($config);
                if ($jail==='' || !isset($state['effective'][$jail])) throw new \RuntimeException('Absent');
                $preview=JailAdmin::preview($state,$jail);
            } catch(\Throwable $e) {$error='Jail inválida, inexistente ou configuração indisponível. Nenhum valor deve ser salvo.';}
            return $this->router->render('jail_editor',['jail'=>$jail,'snapshot'=>$state,'error'=>$error,'preview'=>$preview]);
        }
        $view=JailAdmin::view($config,$_GET);
        $filters=array_map(fn($p)=>basename($p,'.conf'),glob('/etc/fail2ban/filter.d/*.conf')?:[]);
        sort($filters);
        $prefill=['new_jail'=>JailAdmin::name($_GET['new_jail']??null),'filter'=>JailAdmin::name($_GET['filter']??null),
            'logpath'=>'','maxretry'=>'5','findtime'=>'600','bantime'=>'604800'];
        try {$prefill['bantime']=(string)Database::getConfig('global_bantime','604800');}catch(\Throwable $e){}
        foreach(['maxretry','findtime','bantime'] as $key) if(is_string($_GET[$key]??null)&&preg_match('/^-?\d{1,8}$/D',$_GET[$key]))$prefill[$key]=$_GET[$key];
        if (is_string($_GET['logpath']??null) && strlen($_GET['logpath'])<=2048 && str_starts_with($_GET['logpath'],'/var/log/')
            && !str_contains($_GET['logpath'],'..') && !preg_match('/[\x00-\x1F\x7F%]/',$_GET['logpath'])) $prefill['logpath']=$_GET['logpath'];
        return $this->router->render('jails_overview',['view'=>$view,'filters'=>$filters,'prefill'=>$prefill]);
    }

    public function handleAjax(string $do, array $post): string
    {
        $result=JailAdmin::execute($do,$post,$this->router->makeJailConfig());
        if($result['success'])$this->flash($result);
        return json_encode($result,JSON_UNESCAPED_UNICODE);
    }

    private function flash(array $result): void
    {
        Helper::setFlash(!$result['success']?'danger':(!empty($result['warning'])?'warning':'success'),
            $result['message']??$result['error']??'Resultado não confirmado.');
    }
}
