<?php
namespace AMS\Fail2Ban\Controllers;
use AMS\Fail2Ban\{Helper,LogPaths,Router};

class LogPathsController
{
    public function __construct(private array $vars,private Router $router) {}
    public function handle(string $action): string
    {
        Helper::requireAdmin();
        if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
            $do=is_string($_POST['do']??null)?$_POST['do']:'';
            $result=LogPaths::execute($do,$_POST);
            Helper::setFlash($result['success']?(!empty($result['warning'])?'warning':'success'):'danger',$result['message']??$result['error']);
            Helper::redirect(($this->vars['modulelink']??'').'&action=logpaths');return '';
        }
        return $this->router->render('logpaths_overview',['view'=>LogPaths::read($_GET)]);
    }
    public function handleAjax(string $do,array $post): string
    {
        // Mutations retain POST/Redirect/GET, only metadata validation is AJAX.
        return json_encode($do==='validate'?LogPaths::execute($do,$post):['success'=>false,'error'=>'Ação AJAX desconhecida.']);
    }
}
