<?php
namespace AMS\Fail2Ban {
class Helper {public static bool $admin=true;public static function requireAdmin(){if(!self::$admin)throw new \RuntimeException('Unauthorized');}}
class Router {public array $view=[];public function render($name,$data){$this->view=[$name,$data];return 'HTML';}}
class ReportHistory {public static int $exports=0;public static ?string $error=null;public static function read($q){return ['errors'=>[],'exportable'=>true];}public static function csv($q){self::$exports++;if(self::$error==='input')throw new \InvalidArgumentException('Invalid filters');if(self::$error)throw new \RuntimeException('secret database detail');return ['rows'=>2];}}
}
namespace {
require dirname(__DIR__).'/controllers/ReportsController.php';
use AMS\Fail2Ban\{Helper,Router,ReportHistory};
class DownloadFixture extends AMS\Fail2Ban\Controllers\ReportsController {protected function download(array $csv): string{return 'CSV:'.$csv['rows'];}}
$n=0;function rc46($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
$r=new Router;$c=new DownloadFixture([],$r);$_SERVER['REQUEST_METHOD']='GET';$_GET=[];
rc46($c->handle('reports')==='HTML'&&$r->view[0]==='reports_overview','Dedicated view');
$_GET=['do'=>'export_csv'];rc46($c->handle('reports')==='CSV:2','Prepared download');
ReportHistory::$error='input';rc46($c->handle('reports')==='HTML'&&$r->view[1]['view']['errors']===['Invalid filters'],'Input failure before download');
ReportHistory::$error='sql';$c->handle('reports');rc46(!str_contains(implode(' ',$r->view[1]['view']['errors']),'secret'),'No SQL detail exposure');
foreach([[],['do'=>[]],['do'=>'delete']] as $q){$_GET=$q;$_SERVER['REQUEST_METHOD']=$q?'GET':'POST';$before=ReportHistory::$exports;$c->handle('reports');rc46(ReportHistory::$exports===$before&&$r->view[1]['view']['errors']&&!$r->view[1]['view']['exportable'],'No invalid operation');}
Helper::$admin=false;try{$c->handle('reports');rc46(false,'Guest accepted');}catch(RuntimeException $e){rc46($e->getMessage()==='Unauthorized','Direct auth');}
echo "PASS: $n reports controller auth/method/export/error checks; no SQL/provider/native\n";
}
