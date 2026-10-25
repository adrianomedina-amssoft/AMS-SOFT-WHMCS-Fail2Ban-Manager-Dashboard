<?php
namespace AMS\Fail2Ban;

/** Session-bound one-attempt authorizations; no global SQL session or worker cursor. */
final class AIManual
{
    private const KEY='amsfb_ai_manual48';
    public static function start(Router $router,array $post): array
    {
        if(($post['confirm']??null)!=='1')throw new \InvalidArgumentException('Confirme a análise manual e o possível consumo de tokens.');
        if((int)Database::getConfig('schema_version','0')<24)throw new \InvalidArgumentException('Atualize o schema antes de analisar com proteção prévia.');
        $catalog=LogView::catalog($router);$logs=[];$tickets=[];
        // Catalog is not final authorization: the engine validates BehaviorStore::paths again.
        foreach($catalog['logs'] as $row){
            if(!$row['can_analyze'])continue;
            if(count($logs)>=100){$catalog['warnings'][]='Sessão limitada a cem fontes; revise Caminhos de logs.';break;}
            $token=bin2hex(random_bytes(32));$tickets[$token]=['path'=>$row['path'],'at'=>time()];
            $logs[]=['path'=>$row['path'],'label'=>$row['label'],'analysis_token'=>$token];
        }
        $_SESSION[self::KEY]=$tickets; // A new start invalidates unused tickets in other tabs.
        return ['success'=>true,'logs'=>$logs,'warnings'=>$catalog['warnings'],'lines'=>Policy::number('ai_log_lines')];
    }
    public static function consume(array $post): string
    {
        if(($post['confirm']??null)!=='1')throw new \InvalidArgumentException('Confirmação obrigatória.');
        [$path]=LogView::request($post);$token=$post['analysis_token']??null;$tokens=$_SESSION[self::KEY]??[];
        $entry=is_string($token)&&strlen($token)===64?($tokens[$token]??null):null;
        if(!is_array($entry)||($entry['path']??null)!==$path||!is_int($entry['at']??null)||$entry['at']>time()||time()-$entry['at']>=900)throw new \InvalidArgumentException('Confirmação ausente, usada, vencida ou de outra fonte. Inicie uma nova sessão manual.');
        unset($_SESSION[self::KEY][$token]); // Consume before any provider/config/native work, including failures.
        return $path;
    }
    public static function analyze(Router $router,array $post): array
    {
        $path=self::consume($post);
        if((int)Database::getConfig('schema_version','0')<24)throw new \InvalidArgumentException('Schema sem proteção prévia.');
        $row=LogView::allowed(LogView::catalog($router),$path);
        if(!$row['can_analyze'])throw new \InvalidArgumentException('Fonte não disponível para análise.');
        $cfg=AIAnalyzer::getActiveConfig();
        if(empty($cfg['api_key']))throw new \InvalidArgumentException('Configure o provedor em Configurações da IA.');
        $analyzer=new AIAnalyzer($cfg['provider'],$cfg['api_key'],$cfg['model'],$cfg['base_url'],$cfg['protocol']??'',$cfg['reasoning_effort']??'');
        // Keep the existing engine, its cycle lock and final protected-IP recheck unchanged.
        $result=(new AutoBanEngine($analyzer,$router->makeClient()))->analyzePathManual($path);
        unset($result['suggestions']); // Re-query authoritative categories; never insert raw responses as actionable rows.
        return $result;
    }
}
