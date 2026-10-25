<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\{Policy, Router, Helper, Database, Maintenance, BehaviorStore, Privileged};

final class PolicyController
{
    public function __construct(private array $vars, private Router $router) {}

    public function handle(string $action): string
    {
        Helper::requireAdmin();
        $error=null;
        if (($_SERVER['REQUEST_METHOD']??'GET')==='POST') {
            if (!is_string($_POST['csrf_token']??null)||!Helper::checkCsrf($_POST['csrf_token'])) $error='Sessão expirada. Recarregue a página.';
            else try {
                Policy::save($_POST,Helper::adminId(),$_POST['policy_version']??null);
                Helper::setFlash('success','Política salva. Nenhum histórico foi apagado e nenhum IP foi desbloqueado.');
                Helper::redirect(($this->vars['modulelink']??'addonmodules.php?module=amssoft_fail2ban').'&action=protection');
            } catch (\Throwable $e) { $error=self::publicError($e); }
        }
        $effective=Privileged::run(['effective-config']);
        $inventory=!empty($effective['success'])?\AMS\Fail2Ban\ManagedRules::inventory($effective['jails']):null;
        $snapshot=Policy::snapshot();$values=$snapshot['values'];$submitted=$values;
        if($error)foreach($values as $key=>$value)if(isset($_POST[$key])&&is_scalar($_POST[$key]))$submitted[$key]=(string)$_POST[$key];
        $queue=BehaviorStore::health();
        $memory=Policy::number('ai_behavior_hours');$cutoff=date('Y-m-d H:i:s',time()-$memory*3600);
        $base=\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('processing_state','review');
        $reviewCounts=['recent'=>(clone $base)->where('bucket','>=',$cutoff)->count(),'history'=>(clone $base)->where('bucket','<',$cutoff)->count()];
        $reviewView=($_GET['review_view']??'recent')==='history'?'history':'recent';
        $reviewPages=max(1,(int)ceil($reviewCounts[$reviewView]/25));
        $reviewPage=max(1,min($reviewPages,(int)($_GET['review_page']??1)));
        $reviewTasks=(clone $base)->where('bucket',$reviewView==='history'?'<':'>=',$cutoff)->orderByDesc('bucket')->orderBy('id')->offset(($reviewPage-1)*25)->limit(25)->get();
        foreach($reviewTasks as $task)$task->_requeue=BehaviorStore::requeueEligibility((array)$task,time(),$memory);
        return $this->router->render('protection',[
            'managedInventory'=>$inventory,
            'learningQueue'=>json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[],
            'learningUsage'=>[
                'updates'=>\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_logs')->where('action','native_rule_extended')->where('timestamp','>=',date('Y-m-d'))->count(),
                'created'=>\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_logs')->where('action','jail_created')->where('timestamp','>=',date('Y-m-d'))->count(),
            ],
            'fields'=>Policy::fields(),'values'=>$values,'submittedValues'=>$submitted,'error'=>$error,
            'simulation'=>\AMS\Fail2Ban\ProbeSimulation::read(),
            'autoindexReview'=>json_decode(Database::getConfig('autoindex_review_report','{}'),true)?:[],
            'version'=>$snapshot['version'],
            'policyFormVersion'=>$error?(is_string($_POST['policy_version']??null)?$_POST['policy_version']:''):$snapshot['version'],
            'lastRun'=>Database::getConfig('ai_last_run','0'),
            'jobs'=>Maintenance::recent(),
            'reviewTasks'=>$reviewTasks,'reviewCounts'=>$reviewCounts,'reviewView'=>$reviewView,'reviewPage'=>$reviewPage,'reviewPages'=>$reviewPages,
            'heldTasks'=>(int)Database::getConfig('schema_version','0')>=20?\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')
                ->whereColumn('revision','>','analyzed_revision')->where('blocked_until_check_at','>',date('Y-m-d H:i:s'))->orderBy('bucket')->limit(25)->get():[],
            'health'=>[
                'collector'=>Database::getConfig('ai_collector_heartbeat','0'),
                'confirmed_auto'=>Database::getConfig('ai_confirmed_auto','0'),
                'collector_error'=>Database::getConfig('ai_collector_error',''),
                'cycle'=>Database::getConfig('ai_cycle_heartbeat','0'),
                'success'=>Database::getConfig('ai_last_success','0'),
                'error'=>Database::getConfig('ai_last_error',''),
                'usage'=>Database::getConfig('ai_last_usage','{}'),
                'transport'=>json_decode(Database::getConfig('ai_last_transport','null'),true),
                'backlog'=>\WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->whereColumn('revision','>','analyzed_revision')->count(),
                'queue'=>$queue,
                'retired_local'=>\AMS\Fail2Ban\RetiredRoutes::health(),
                'simple_local'=>\AMS\Fail2Ban\LocalObservation::health(),
                'telemetry'=>\AMS\Fail2Ban\QueueTelemetry::summary($queue),
                'promotion'=>json_decode(Database::getConfig('ai_last_promotion_result','null'),true),
                'jail'=>Privileged::run(['ai-jail-health']),
                'calls'=>Database::getConfig('ai_last_cycle_calls'),
                'retry_calls'=>Database::getConfig('ai_last_cycle_retry_calls'),
                'native_detection_quarantine'=>json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[],
                'native_repairs'=>array_filter(array_combine(
                    ['amsfb-apache-env-probe','amsfb-apache-git-probe','amsfb-apache-cms-probe'],
                    array_map(fn($j)=>Database::getConfig('native_repair_pending_'.$j,''),['amsfb-apache-env-probe','amsfb-apache-git-probe','amsfb-apache-cms-probe'])
                )),
            ],
        ]);
    }

    public function handleAjax(string $do,array $post): string
    {
        if(Helper::adminId()<1)return json_encode(['success'=>false,'error'=>'Acesso administrativo obrigatório.']);
        if(!is_string($post['csrf_token']??null)||!Helper::checkCsrf($post['csrf_token']))return json_encode(['success'=>false,'error'=>'Sessão expirada. Recarregue a página.']);
        try {
            foreach($post as $value)if(!is_string($value)||strlen($value)>16384)throw new \InvalidArgumentException('Parâmetro inválido ou excessivo.');
            $result=match($do) {
                'preview'=>Maintenance::preview($post,Helper::adminId(),$this->router->makeClient()),
                'queue'=>Maintenance::queue($post,Helper::adminId()),
                'retry'=>Maintenance::retry($post,Helper::adminId()),
                'requeue'=>BehaviorStore::requeue((string)($post['task']??''),Helper::adminId()),
                default=>throw new \InvalidArgumentException('Operação inválida'),
            };
            return json_encode(['success'=>true]+$result);
        } catch (\Throwable $e) { return json_encode(['success'=>false,'error'=>self::publicError($e)]); }
    }

    private static function publicError(\Throwable $e): string
    {
        if($e instanceof \InvalidArgumentException||$e instanceof \AMS\Fail2Ban\ProtectionFailure)return $e->getMessage();
        error_log('[AMSFB] Protection operation failed: '.get_class($e));
        return 'Não foi possível confirmar a operação. Confira os valores atuais e o histórico de trabalhos antes de tentar novamente; verifique os logs do módulo.';
    }
}
