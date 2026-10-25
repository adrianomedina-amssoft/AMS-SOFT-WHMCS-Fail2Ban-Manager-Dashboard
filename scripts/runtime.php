<?php
// Root-only operational entry point. Never bootstrap WHMCS hooks/HTTP sessions.
if(PHP_SAPI!=='cli'||!function_exists('posix_geteuid')||posix_geteuid()!==0) exit(1);
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
$capsule=new WHMCS\Database\Capsule();
$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,'username'=>$db_username,
    'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
use AMS\Fail2Ban\{Database,Migrations,Maintenance,AutoBanEngine,AIAnalyzer,Fail2BanClient,Policy};
$operation=$argv[1]??'status';
$client=new Fail2BanClient('/usr/bin/sudo','/usr/bin/fail2ban-client');
switch($operation) {
    case 'migrate':
        if((int)WHMCS\Database\Capsule::selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Ciclo ativo; tente novamente.');
        try {
            Migrations::run();
            $membersColumn=WHMCS\Database\Capsule::selectOne("SHOW COLUMNS FROM mod_amssoft_fail2ban_rollups LIKE 'campaign_members'");
            if($membersColumn && strtolower($membersColumn->Type)==='text')
                WHMCS\Database\Capsule::statement('ALTER TABLE mod_amssoft_fail2ban_rollups MODIFY campaign_members LONGTEXT NULL');
            if(Database::getConfig('campaign_baseline_v18','0')!=='1') {
                $groups=WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->select('source_log','pattern')->distinct()->get();
                foreach($groups as $group)WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')
                    ->where('source_log',$group->source_log)->where('pattern',$group->pattern)
                    ->update(['campaign_signature'=>\AMS\Fail2Ban\BehaviorStore::campaignSignature($group->source_log,$group->pattern),
                        'campaign_members'=>json_encode(\AMS\Fail2Ban\BehaviorStore::campaignMembers($group->source_log,$group->pattern))]);
                Database::setConfig('campaign_baseline_v18','1');
            }
            echo "Schema ".Migrations::VERSION."\n";
        }
        finally {WHMCS\Database\Capsule::selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}break;
    case 'repair-current-detection':
        $audit=json_decode(file_get_contents($argv[2]??''),true,512,JSON_THROW_ON_ERROR);
        $manifest=array_column($audit,null,'filter');$db=WHMCS\Database\Capsule::connection();$locked=false;
        if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Ciclo ativo.');
        try {
            $locked=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;
            if(!$locked)throw new RuntimeException('Política ocupada.');
            foreach(['amsfb-apache-env-probe','amsfb-apache-wp-probe'] as $name) {
                if(empty($manifest[$name]['sha256']))throw new RuntimeException('Manifesto incompleto.');
                if($name==='amsfb-apache-wp-probe') {
                    // No proven WordPress positive in the current audit. Do not
                    // keep a mislabeled .env detector or unproven error branches.
                    $result=\AMS\Fail2Ban\Privileged::run(['quarantine-detection',$name,$manifest[$name]['sha256']]);
                } else {
                    $evidence=[];
                    foreach($manifest[$name]['patterns'] as $p){foreach($p['examples'] as $e)$evidence[]=$e['line'];foreach($p['positives'] as $e)$evidence[]=$e;}
                    $candidate=tempnam('/tmp','amsfb_filter_');$proof=tempnam('/tmp','amsfb_evidence_');
                    try {
                        file_put_contents($candidate,file_get_contents(dirname(__DIR__).'/setup/fail2ban/filter.d/'.$name.'.conf'));
                        file_put_contents($proof,json_encode(array_values(array_unique($evidence))));
                        $result=\AMS\Fail2Ban\Privileged::run(['replace-filter',$candidate,$name,$manifest[$name]['sha256'],$proof]);
                    } finally {unlink($candidate);unlink($proof);}
                }
                if(empty($result['success']))throw new RuntimeException($name.': '.($result['error']??'Falha privilegiada'));
                if(!empty($result['quarantined'])) {
                    $q=json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[];
                    Database::setConfig('native_detection_quarantine',json_encode(array_values(array_unique(array_merge($q,$result['consumers'])))));
                }
                Database::logEvent('',$name,!empty($result['quarantined'])?'native_detection_quarantined':'native_filter_repaired',json_encode($result));
                echo json_encode(['filter'=>$name]+$result)."\n";
            }
        } finally {if($locked)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
        break;
    case 'repair-native':
        // Explicit root-only deployment of audited legacy defects, no broad
        // jail edits and no restoration/recreation of historical bans.
        $audit=json_decode(file_get_contents($argv[2]??''),true,512,JSON_THROW_ON_ERROR);
        $manifest=array_column($audit,null,'filter');
        $db=WHMCS\Database\Capsule::connection();$policyLocked=false;
        if((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',30) AS acquired")->acquired!==1)throw new RuntimeException('Ciclo ativo.');
        try {
            $policyLocked=(int)$db->selectOne("SELECT GET_LOCK('amsfb_policy',5) AS acquired")->acquired===1;
            if(!$policyLocked)throw new RuntimeException('Política em uso.');
            foreach(['amsfb-apache-git-probe','amsfb-apache-git-scanner','amsfb-apache-auth'] as $name) {
                if(empty($manifest[$name]['sha256']))throw new RuntimeException('Inventário ausente: '.$name);
                $evidence=[];
                foreach($manifest[$name]['patterns'] as $pattern) {
                    foreach($pattern['positives'] as $line)$evidence[]=$line;
                    foreach($pattern['examples'] as $example)$evidence[]=$example['line'];
                }
                if($name==='amsfb-apache-auth') {
                    $result=\AMS\Fail2Ban\Privileged::run(['quarantine-detection',$name,$manifest[$name]['sha256']]);
                } else {
                    $candidate=tempnam('/tmp','amsfb_filter_');$proof=tempnam('/tmp','amsfb_evidence_');
                    try {
                        file_put_contents($candidate,file_get_contents(dirname(__DIR__).'/setup/fail2ban/filter.d/'.$name.'.conf'));
                        file_put_contents($proof,json_encode(array_values(array_unique($evidence))));
                        $result=\AMS\Fail2Ban\Privileged::run(['replace-filter',$candidate,$name,$manifest[$name]['sha256'],$proof]);
                    } finally {unlink($candidate);unlink($proof);}
                }
                if(empty($result['success']))throw new RuntimeException($name.': '.($result['error']??'Falha na ponte'));
                if($name==='amsfb-apache-auth') {
                    $quarantine=json_decode(Database::getConfig('native_detection_quarantine','[]'),true)?:[];
                    Database::setConfig('native_detection_quarantine',json_encode(array_values(array_unique(array_merge($quarantine,$result['consumers'])))));
                }
                Database::logEvent('',$name,!empty($result['quarantined'])?'native_detection_quarantined':'native_filter_repaired',json_encode($result));
                echo json_encode(['filter'=>$name]+$result)."\n";
            }
        } finally {
            if($policyLocked)$db->selectOne("SELECT RELEASE_LOCK('amsfb_policy')");
            $db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");
        }
        break;
    case 'collect': echo json_encode(AutoBanEngine::collectLocal(),JSON_PRETTY_PRINT)."\n"; break;
    case 'tick': Maintenance::tick($client); echo "Worker executado\n"; break;
    case 'drain-transition':
        $id=$argv[2]??'';if(!preg_match('/^[a-f0-9]{32}$/D',$id))throw new InvalidArgumentException('ID inválido.');
        $deadline=microtime(true)+600;
        do {
            Maintenance::tick($client);
            $job=WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$id)->first();
            if(!$job)throw new RuntimeException('Trabalho inexistente.');
            $result=json_decode($job->result??'',true)?:[];
            echo json_encode(['job'=>$id,'status'=>$job->status,'processed'=>$result['target_index']??0,'error'=>$result['error']??null])."\n";
            if(!in_array($job->status,['queued','running'],true))break;
            usleep(250000);
        } while(microtime(true)<$deadline);
        break;
    case 'resume-transition':
        echo json_encode(Maintenance::retry(['job'=>$argv[2]??'','confirmation'=>$argv[3]??''],0))."\n";break;
    case 'automatic-cycle':
    case 'analyze':
        if($operation==='automatic-cycle'&&Database::getConfig('ai_auto_enabled','0')!=='1')throw new RuntimeException('Automação desativada.');
        $cfg=AIAnalyzer::getActiveConfig();
        if(empty($cfg['api_key']))throw new RuntimeException('Credencial indisponível.');
        $engine=new AutoBanEngine(new AIAnalyzer($cfg['provider'],$cfg['api_key'],$cfg['model'],$cfg['base_url'],$cfg['protocol'],$cfg['reasoning_effort']),$client);
        $result=$engine->runAnalysis($operation==='analyze');
        if($operation==='automatic-cycle'&&!isset($result['_locked_out']))Database::setConfig('ai_last_run',(string)time());
        echo json_encode($result,JSON_PRETTY_PRINT)."\n"; break;
    case 'probe':
        $cfg=AIAnalyzer::getActiveConfig();
        if(empty($cfg['api_key']))throw new RuntimeException('Credencial indisponível.');
        $analyzer=new AIAnalyzer($cfg['provider'],$cfg['api_key'],$cfg['model'],$cfg['base_url'],$cfg['protocol'],$cfg['reasoning_effort']);
        $analyzer->setRequestTimeout(30);
        $ok=$analyzer->ping();
        echo json_encode(['provider'=>$cfg['provider'],'model'=>$cfg['model'],'success'=>$ok,'usage'=>$analyzer->usage()])."\n";
        if(!$ok)exit(2);
        break;
    case 'verify-analysis':
        $cfg=AIAnalyzer::getActiveConfig();
        $analyzer=new AIAnalyzer($cfg['provider'],$cfg['api_key'],$cfg['model'],$cfg['base_url'],$cfg['protocol'],$cfg['reasoning_effort']);
        $stamp=date('d/M/Y:H:i:s O');
        $normal='198.51.100.10 - - ['.$stamp.'] "GET /clientarea.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
        $attack='203.0.113.7 - - ['.$stamp.'] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
        $items=$analyzer->analyzeSubjects([$normal,$attack],['198.51.100.10'=>['events'=>1],'203.0.113.7'=>['events'=>3,'ips'=>2]]);
        $bound=\AMS\Fail2Ban\Safety::bindSuggestions($items,[$normal,$attack]);
        $summary=[];
        foreach($bound as $s)$summary[]=['ip'=>$s['ip'],'classification'=>$s['action'],'confidence'=>$s['confidence'],
            'exact_evidence'=>$s['_evidence_validated'],'filter_valid'=>$s['action']==='ban'?AutoBanEngine::validateEvidenceFilter($s):null,'regex'=>$s['failregex']];
        echo json_encode(['classified'=>$summary,'usage'=>$analyzer->usage()],JSON_PRETTY_PRINT)."\n";
        break;
    case 'prepare-policy':
        $defaults=[];foreach(Policy::fields() as $key=>$f)$defaults[$key]=(string)$f[2];
        $defaults['ai_mode']='threshold';$defaults['ai_auto_enabled']='0';$defaults['ai_auto_create_filter']='1';
        Policy::save($defaults,0,Database::getConfig('policy_version','0'));
        echo "Política aprovada preparada; IA ainda sem bloqueios automáticos.\n";break;
    case 'freeze-policy':
        Policy::save([],0,Database::getConfig('policy_version','0'));echo "Política efetiva persistida integralmente e jail dedicada conferida.\n";break;
    case 'queue-monitor':
        $preview=Maintenance::previewForRootCli(['kind'=>'monitor','scope'=>'ai','clear_logs'=>'0','clear_suggestions'=>'0','clear_observations'=>'0'],$client);
        echo json_encode(Maintenance::queueForRootCli(['nonce'=>$preview['nonce'],'confirmation'=>'EXECUTAR MANUTENCAO']))."\n";
        break;
    case 'queue-transition':
        if(($argv[2]??'')!=='EXECUTAR MANUTENCAO')throw new InvalidArgumentException('Confirmação explícita necessária.');
        $preview=Maintenance::previewForRootCli(['kind'=>'both','scope'=>'all','monitor'=>'1'],$client);
        $job=WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$preview['nonce'])->first();
        $payload=json_decode($job->payload,true);
        $payload['resume_policy']=['ai_auto_enabled'=>'1','ai_mode'=>'threshold','ai_auto_create_filter'=>'1','confirm_auto'=>'1'];
        WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_jobs')->where('id',$job->id)->update(['payload'=>json_encode($payload)]);
        echo json_encode(['preview'=>['bans'=>$preview['bans'],'records'=>$preview['records'],'cutoff'=>$preview['cutoff']],
            'queued'=>Maintenance::queueForRootCli(['nonce'=>$job->id,'confirmation'=>$argv[2]])],JSON_PRETTY_PRINT)."\n";
        break;
    case 'review-quarantine':
        $quarantine=parse_ini_file('/etc/fail2ban/jail.d/99-amsfb-quarantine.local',true,INI_SCANNER_RAW)?:[];
        $effective=\AMS\Fail2Ban\Privileged::run(['effective-config']);
        $manager=new \AMS\Fail2Ban\FilterManager('/etc/fail2ban/filter.d/',new \AMS\Fail2Ban\JailConfig('/etc/fail2ban/jail.local',$client),$client);
        $review=[];
        foreach($quarantine as $jail=>$settings) {
            $name=\AMS\Fail2Ban\Safety::filterName($effective['jails'][$jail]['filter']??$jail);
            $rows=WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->whereIn('filter_name',[$name,'amsfb-'.$name])->where('confidence','>=',90)->limit(100)->get();
            $evidence=[];
            foreach($rows as $row)foreach(json_decode($row->evidence??'[]',true)?:[] as $line)if(is_string($line))$evidence[]=$line;
            $safe=$evidence&&$manager->isFilterSafe($name,array_slice(array_unique($evidence),0,100));
            $review[]=['jail'=>$jail,'filter'=>$name,'evidence_lines'=>count($evidence),'all_regex_proven'=>$safe,
                'decision'=>'Manter quarentena; reativação exige ação individual com validação efetiva.'];
        }
        echo json_encode(['reviewed'=>count($review),'review'=>$review],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)."\n";break;
    case 'status':
        echo json_encode(['schema'=>Database::getConfig('schema_version'),'policy'=>Policy::values(),
            'queue'=>\AMS\Fail2Ban\BehaviorStore::health(),
            'telemetry'=>\AMS\Fail2Ban\QueueTelemetry::summary(),
            'promotion'=>json_decode(Database::getConfig('ai_last_promotion_result','null'),true),
            'native_detection_quarantine'=>json_decode(Database::getConfig('native_detection_quarantine','[]'),true),
            'heartbeat'=>Database::getConfig('ai_cycle_heartbeat'),'collector'=>Database::getConfig('ai_collector_heartbeat'),
            'last_error'=>Database::getConfig('ai_last_error'),'jobs'=>Maintenance::recent()],JSON_PRETTY_PRINT|JSON_INVALID_UTF8_SUBSTITUTE)."\n"; break;
    default: throw new InvalidArgumentException('Operação desconhecida.');
}
