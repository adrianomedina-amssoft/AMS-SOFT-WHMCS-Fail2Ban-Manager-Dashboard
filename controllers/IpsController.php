<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\{Helper, Router, IpBanActions, IpBanView};

class IpsController
{
    public function __construct(private array $vars,private Router $router) {}

    public function handle(string $action): string
    {
        if(($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
            $operation=is_string($_POST['do']??null)?$_POST['do']:'';
            $result=IpBanActions::execute($operation,$_POST,$this->router->makeClient());
            $this->flash($result);
            Helper::redirect(($this->vars['modulelink']??'').'&action=ips');
            return '';
        }
        return $this->router->render('ips_overview',['view'=>IpBanView::read($this->vars,$_GET)]);
    }

    public function handleAjax(string $do,array $post): string
    {
        $result=IpBanActions::execute($do,$post,$this->router->makeClient());
        if($result['success'])$this->flash($result);
        return json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE);
    }

    private function flash(array $result): void
    {
        Helper::setFlash($result['success']?(!empty($result['warning'])?'warning':'success'):'danger',
            $result['message']??$result['error']);
    }
}
