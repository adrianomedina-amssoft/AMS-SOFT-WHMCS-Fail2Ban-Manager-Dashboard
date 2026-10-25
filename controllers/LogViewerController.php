<?php
namespace AMS\Fail2Ban\Controllers;
use AMS\Fail2Ban\{Helper,Router,LogView,Database,Policy,AIAnalyzer,AutoBanEngine};

class LogViewerController
{
    public function __construct(private array $vars,private Router $router) {}
    private static function token(): string
    {
        $tokens=$_SESSION['amsfb_view_analysis']??[];
        foreach($tokens as $key=>$at)if(!is_int($at)||time()-$at>=900)unset($tokens[$key]);
        $tokens=array_slice($tokens,-4,null,true);$token=bin2hex(random_bytes(32));$tokens[$token]=time();$_SESSION['amsfb_view_analysis']=$tokens;return $token;
    }
    public function handle(string $action): string
    {
        Helper::requireAdmin();$view=LogView::catalog($this->router);
        $view['analysis_token']=self::token();$view['analysis_lines']=Policy::number('ai_log_lines');
        if(($_SERVER['REQUEST_METHOD']??'GET')!=='GET')$view['warnings'][]='Esta página é somente leitura; nenhuma ação foi executada.';
        return $this->router->render('logviewer_overview',['view'=>$view]);
    }
    public function handleAjax(string $do,array $post): string
    {
        $result=['success'=>false,'error'=>'Ação desconhecida.'];
        if(Helper::adminId()<=0||($_SERVER['REQUEST_METHOD']??'GET')!=='POST')return json_encode(['success'=>false,'error'=>'Consulta exige sessão administrativa e POST.']);
        if(!is_string($post['csrf_token']??null)||!Helper::checkCsrf($post['csrf_token']))return json_encode(['success'=>false,'error'=>'Token CSRF inválido.']);
        try{
            if($do==='fetch_lines')$result=LogView::fetch($this->router,$post);
            elseif($do==='ban_ip')$result=['success'=>false,'error'=>'Use Revisar IP na tela de IPs para confirmar o banimento. Nenhuma jail ou ban foi alterado por este endpoint.'];
            elseif($do==='analyze')$result=$this->analyze($post);
        }catch(\InvalidArgumentException $e){$result=['success'=>false,'error'=>$e->getMessage()];}
        catch(\Throwable $e){$result=['success'=>false,'error'=>$do==='analyze'?'Resultado da análise não confirmado. Confira a aba IA antes de repetir; não houve reenvio automático.':'Leitura indisponível ou arquivo alterado. Atualize novamente; isso não confirma arquivo vazio.'];}
        return json_encode($result,JSON_INVALID_UTF8_SUBSTITUTE);
    }
    private function analyze(array $post): array
    {
        [$path]=LogView::request($post);
        if(($post['confirm']??null)!=='1')throw new \InvalidArgumentException('Confirme a análise manual e o possível consumo de tokens.');
        $token=$post['analysis_token']??null;$tokens=$_SESSION['amsfb_view_analysis']??[];
        if(!is_string($token)||strlen($token)!==64||!isset($tokens[$token])||!is_int($tokens[$token])||$tokens[$token]>time()||time()-$tokens[$token]>=900)throw new \InvalidArgumentException('Confirmação ausente, usada ou vencida. Atualize a página antes de solicitar outra análise.');
        unset($_SESSION['amsfb_view_analysis'][$token]);
        try{
            $row=LogView::allowed(LogView::catalog($this->router),$path);
            if(!$row['can_analyze'])throw new \InvalidArgumentException('Log operacional do Fail2Ban é somente visualização.');
            if((int)Database::getConfig('schema_version','0')<20)throw new \InvalidArgumentException('Atualize o schema antes de usar análise manual com proteção prévia.');
            $cfg=AIAnalyzer::getActiveConfig();if(empty($cfg['api_key']))throw new \InvalidArgumentException('Configure um provedor na aba IA antes de analisar.');
            $analyzer=new AIAnalyzer($cfg['provider'],$cfg['api_key'],$cfg['model'],$cfg['base_url'],$cfg['protocol']??'',$cfg['reasoning_effort']??'');
            // Existing engine owns source validation, cycle lock, whitelist,
            // protected-IP admission and the final pre-provider recheck.
            $result=(new AutoBanEngine($analyzer,$this->router->makeClient()))->analyzePathManual($path);
            return $result+['analysis_token'=>self::token()];
        }catch(\Throwable $e){throw $e;} // Consumed token stays consumed even if the outcome is uncertain.
    }
}
