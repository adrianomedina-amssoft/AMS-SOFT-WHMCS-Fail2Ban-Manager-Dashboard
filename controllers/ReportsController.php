<?php
namespace AMS\Fail2Ban\Controllers;
use AMS\Fail2Ban\{Helper,ReportHistory,Router};
class ReportsController
{
    public function __construct(private array $vars,private Router $router) {}
    public function handle(string $action): string
    {
        Helper::requireAdmin();$error=null;$do=$_GET['do']??'';
        if(($_SERVER['REQUEST_METHOD']??'GET')!=='GET')$error='Relatórios aceitam somente consultas GET; nenhuma alteração foi feita.';
        elseif(!is_string($do)||!in_array($do,['','export_csv'],true))$error='Ação de relatório desconhecida.';
        elseif($do==='export_csv'){
            try{$csv=ReportHistory::csv($_GET);return $this->download($csv);}
            catch(\InvalidArgumentException $e){$error=$e->getMessage();}
            catch(\Throwable $e){$error='Exportação não concluída. Verifique a disponibilidade do histórico e tente novamente; nenhum CSV parcial foi enviado.';}
        }
        $view=ReportHistory::read($_GET);
        if($error){$view['errors'][]=$error;$view['exportable']=false;}
        return $this->router->render('reports_overview',['view'=>$view]);
    }
    protected function download(array $csv): string
    {
        if(headers_sent()){fclose($csv['stream']);throw new \RuntimeException('Headers already sent');}
        while(ob_get_level()>0){if(!ob_end_clean()){fclose($csv['stream']);throw new \RuntimeException('Output buffer unavailable');}}
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="fail2ban_report_'.date('Ymd_His').'.csv"');
        header('Cache-Control: private, no-store, max-age=0');header('Pragma: no-cache');header('X-Content-Type-Options: nosniff');
        header('X-Report-Rows: '.$csv['rows']);header('X-GeoIP-Source: local-cache-only');
        if(session_status()===PHP_SESSION_ACTIVE)session_write_close();
        fpassthru($csv['stream']);fclose($csv['stream']);exit;
    }
}
