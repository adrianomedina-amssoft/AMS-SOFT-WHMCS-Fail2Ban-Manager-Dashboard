<?php
if(PHP_SAPI!=='cli')exit(1);
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\ProtectionFailure;
$public=new ReflectionMethod(AMS\Fail2Ban\Controllers\PolicyController::class,'publicError');
$n=0;function ep($ok,$why){global $n;if(!$ok)throw new RuntimeException($why);$n++;}
foreach(['policy_busy','api_key_required','whitelist_unconfirmed','jail_unconfirmed','probes_unconfirmed','routes_unconfirmed','native_reconciliation','routes_reconciliation','probes_reconciliation','retry_not_allowed','retry_policy_changed','retry_backup_incomplete','retry_archive_unverified'] as $reason){
    $cause=new RuntimeException('private SQL token path');$error=new ProtectionFailure($reason,$cause);
    ep($error instanceof RuntimeException&&$error->getPrevious()===$cause,'Compatibility/cause lost');
    $message=$public->invoke(null,$error);
    ep($message===$error->getMessage()&&!str_contains($message,'private'),'Known reason hidden or cause leaked');
}
ini_set('error_log','/dev/null');
foreach([new RuntimeException('private SQL token path'),new TypeError('private stack'),new RuntimeException('Configuração não salva; reconciliação nativa pendente. Verifique o módulo.')] as $error){
    $message=$public->invoke(null,$error);
    ep($message!==$error->getMessage()&&!str_contains($message,'private'),'Untrusted exception promoted by matching its text');
}
ep($public->invoke(null,new InvalidArgumentException('Confirme a execução automática de bloqueios'))==='Confirme a execução automática de bloqueios','Input validation hidden');
try{new ProtectionFailure('private arbitrary message');ep(false,'Open vocabulary');}catch(LogicException $e){ep(!str_contains($e->getMessage(),'private'),'Unknown reason leaked');}
echo "PASS: {$n} closed public-error vocabulary checks; no SQL/native/provider\n";
