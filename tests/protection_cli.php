<?php
namespace AMS\Fail2Ban;
if(\PHP_SAPI!=='cli')exit(1);
// Namespace-only context fixtures; production never loads these functions/constants.
define(__NAMESPACE__.'\\PHP_SAPI',$argv[1]??'cli');
$GLOBALS['fixture_euid']=(int)($argv[2]??0);$GLOBALS['fixture_posix']=($argv[3]??'1')==='1';
function posix_geteuid(){return $GLOBALS['fixture_euid'];}
function function_exists($name){return $name==='posix_geteuid'?$GLOBALS['fixture_posix']:\function_exists($name);}
class Fail2BanClient {}
require dirname(__DIR__).'/lib/Maintenance.php';
$root=PHP_SAPI==='cli'&&posix_geteuid()===0&&function_exists('posix_geteuid');$n=0;
foreach([
    [fn()=>Maintenance::previewForRootCli([],new Fail2BanClient),$root?'Operação/escopo inválido.':'Operação exclusiva do terminal root.'],
    [fn()=>Maintenance::queueForRootCli([]),$root?'Prévia inválida.':'Operação exclusiva do terminal root.'],
    [fn()=>Maintenance::preview([],0,new Fail2BanClient),'Administrador inválido.'],
    [fn()=>Maintenance::queue([],0),'Administrador inválido.'],
] as [$call,$message]){
    try{$call();throw new \RuntimeException('Invalid input accepted');}
    catch(\InvalidArgumentException $e){if($e->getMessage()!==$message)throw new \RuntimeException('Wrong boundary: '.$e->getMessage());$n++;}
}
echo "PASS: {$n} root CLI/web/anonymous boundary checks; simulated SAPI/UID, no SQL/native\n";
