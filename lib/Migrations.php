<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

final class Migrations
{
    public const VERSION = 37;

    public static function run(): void
    {
        if ((int)Database::getConfig('schema_version', '0') >= self::VERSION && Database::getConfig('schema37_complete','0')==='1') return;
        $lock = Capsule::selectOne("SELECT GET_LOCK('amssoft_fail2ban_schema', 10) AS acquired");
        if ((int)$lock->acquired !== 1) throw new \RuntimeException('Migração em andamento.');
        try {
            if ((int)Database::getConfig('schema_version', '0') >= self::VERSION && Database::getConfig('schema37_complete','0')==='1') return;
            if ((int)Database::getConfig('schema_version','0')>=36 && Database::getConfig('schema36_complete','0')==='1') {self::finish37();return;}
            if ((int)Database::getConfig('schema_version','0')>=35 && Database::getConfig('schema35_complete','0')==='1') {self::finish36();return;}
            if ((int)Database::getConfig('schema_version','0')>=34 && Database::getConfig('schema34_complete','0')==='1') {self::finish35();return;}
            if ((int)Database::getConfig('schema_version','0')>=33 && Database::getConfig('schema33_complete','0')==='1') {self::finish34();return;}
            if ((int)Database::getConfig('schema_version','0')>=32 && Database::getConfig('schema32_complete','0')==='1') {self::finish33();return;}
            if ((int)Database::getConfig('schema_version','0')>=31 && Database::getConfig('schema31_complete','0')==='1') {self::finish32();return;}
            if ((int)Database::getConfig('schema_version','0')>=30 && Database::getConfig('schema30_complete','0')==='1') {self::finish31();return;}
            if ((int)Database::getConfig('schema_version','0')>=29 && Database::getConfig('schema29_complete','0')==='1') {
                self::finish30();return;
            }
            if ((int)Database::getConfig('schema_version','0')>=28 && Database::getConfig('schema28_complete','0')==='1') {
                self::finish29();return;
            }
            if ((int)Database::getConfig('schema_version','0')>=23 && Database::getConfig('schema23_complete','0')==='1') {
                DecisionProtection::migrate();self::finish28();return;
            }
            if ((int)Database::getConfig('schema_version','0')>=22 && Database::getConfig('schema22_complete','0')==='1') {
                self::structuralColumns();
                DecisionMemory::migrate(); AnalysisWork::migrate();
                DecisionProtection::migrate();self::finish28();Database::setConfig('schema23_complete','1');
                return;
            }
            if ((int)Database::getConfig('schema_version', '0') < 14) {
            // Safe legacy migrations only. Never run the narrowing ENUM migrations.
            foreach ([2, 3, 4, 5, 6] as $version) {
                $fn = 'amssoft_fail2ban_migrate_v' . $version;
                if (function_exists($fn)) $fn();
            }
            if (!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions', 'source_log')) {
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions', function ($t) {
                    $t->string('source_log', 500)->nullable();
                });
            }
            Capsule::statement('ALTER TABLE mod_amssoft_fail2ban_logs MODIFY action VARCHAR(40) NOT NULL, MODIFY reason TEXT NULL');
            $indexes = Capsule::select("SHOW INDEX FROM mod_amssoft_fail2ban_ai_suggestions WHERE Key_name = 'amsfb_filter_window'");
            if (!$indexes) {
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions', function ($t) {
                    $t->index(['filter_name', 'created_at', 'status'], 'amsfb_filter_window');
                });
            }
            if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_detections')) {
                Capsule::schema()->create('mod_amssoft_fail2ban_detections', function ($t) {
                    $t->charset = 'utf8mb4';
                    $t->collation = 'utf8mb4_unicode_ci';
                    $t->char('fingerprint', 64)->primary();
                    $t->string('ip', 45)->index();
                    $t->unsignedBigInteger('suggestion_id')->index();
                    $t->string('source_log', 500)->nullable();
                    $t->text('evidence')->nullable();
                    $t->timestamp('detected_at')->useCurrent()->index();
                });
            }
            foreach (['source_log', 'evidence'] as $column) {
                if (!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections', $column)) {
                    Capsule::schema()->table('mod_amssoft_fail2ban_detections', function ($t) use ($column) {
                        if ($column === 'source_log') $t->string($column, 500)->nullable();
                        else $t->text($column)->nullable();
                    });
                }
            }
            foreach (['config', 'logs', 'ai_suggestions', 'geo_cache', 'detections'] as $suffix) {
                Capsule::statement('ALTER TABLE mod_amssoft_fail2ban_' . $suffix . ' CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
            }
            // Recover only unambiguous historical events; retain unknown rows.
            Capsule::table('mod_amssoft_fail2ban_logs')->where('action', '')
                ->where('reason', 'like', 'Teto % lotes atingido%')->update(['action' => 'batch_limit_reached']);
            Capsule::table('mod_amssoft_fail2ban_logs')->where('action', '')
                ->where(function ($q) {
                    $q->where('reason', 'like', 'Truncated:%')
                        ->orWhere('reason', 'like', 'InvalidJSON:%')
                        ->orWhere('reason', 'like', 'Retry esgotado:%');
                })->update(['action' => 'ai_parse_error']);
            }
            if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_rollups')) {
                Capsule::schema()->create('mod_amssoft_fail2ban_rollups', function ($t) {
                    $t->charset='utf8mb4'; $t->collation='utf8mb4_unicode_ci';
                    $t->char('id',64)->primary();
                    $t->string('ip',45)->index(); $t->string('source_log',500);
                    $t->char('pattern',64)->index(); $t->timestamp('bucket')->index();
                    $t->unsignedInteger('events')->default(0);
                    $t->unsignedInteger('revision')->default(0);
                    $t->unsignedInteger('analyzed_revision')->default(0);
                    $t->longText('samples');
                    $t->timestamp('retry_at')->nullable()->index();
                    $t->unsignedInteger('attempts')->default(0);
                    $t->timestamp('updated_at')->useCurrent();
                });
            }
            if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_jobs')) {
                Capsule::schema()->create('mod_amssoft_fail2ban_jobs',function($t) {
                    $t->charset='utf8mb4'; $t->collation='utf8mb4_unicode_ci';
                    $t->char('id',32)->primary(); $t->unsignedInteger('admin_id');
                    $t->string('status',32)->index(); $t->longText('payload');
                    $t->longText('result')->nullable(); $t->timestamp('created_at')->useCurrent();
                    $t->timestamp('updated_at')->useCurrent();
                });
            }
            foreach(['event_id'=>64,'pattern'=>64] as $column=>$length) {
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections',$column)) {
                    Capsule::schema()->table('mod_amssoft_fail2ban_detections',function($t)use($column,$length){$t->string($column,$length)->nullable()->index();});
                }
            }
            foreach(['filter_name'=>50,'confidence'=>3] as $column=>$length) {
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_detections',function($t)use($column,$length){$t->string($column,$length)->nullable()->index();});
            }
            foreach(['classification'=>16,'pattern'=>64] as $column=>$length) {
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t)use($column,$length){$t->string($column,$length)->nullable()->index();});
            }
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions','updated_at'))
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t){$t->timestamp('updated_at')->nullable()->index();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_logs','source_event'))
                Capsule::schema()->table('mod_amssoft_fail2ban_logs',function($t){$t->char('source_event',64)->nullable()->unique();});
            foreach(['processing_state'=>16,'failure_code'=>40,'failure_detail'=>500] as $column=>$length) {
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t)use($column,$length){
                        if($column==='processing_state')$t->string($column,$length)->default('pending')->index();
                        else $t->string($column,$length)->nullable();
                    });
            }
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','validation_attempts'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->unsignedInteger('validation_attempts')->default(0);});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','campaign_signature'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->char('campaign_signature',64)->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','last_revisit_at'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->timestamp('last_revisit_at')->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','campaign_members'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->longText('campaign_members')->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions','analysis_key'))
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t){$t->char('analysis_key',64)->nullable()->index();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions','task_id'))
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t){$t->char('task_id',64)->nullable()->index();});
            if((int)Database::getConfig('schema_version','0')<18) {
                // Baseline only: migration must not reopen historical tasks.
                $groups=Capsule::table('mod_amssoft_fail2ban_rollups')->select('source_log','pattern')->distinct()->get();
                foreach($groups as $group) {
                    $signature=BehaviorStore::campaignSignature($group->source_log,$group->pattern);
                    Capsule::table('mod_amssoft_fail2ban_rollups')->where('source_log',$group->source_log)->where('pattern',$group->pattern)
                        ->whereNull('campaign_signature')->update(['campaign_signature'=>$signature,
                            'campaign_members'=>json_encode(BehaviorStore::campaignMembers($group->source_log,$group->pattern))]);
                }
                foreach(['ai_campaign_revisit_minutes','ai_queue_urgent_enabled','ai_queue_alert_minutes'] as $key)
                    Database::setConfig($key,Database::getConfig($key,(string)Policy::fields()[$key][2]));
            }
            foreach(['total_attempts','total_validation_attempts','recovery_rounds'] as $column) {
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t)use($column){$t->unsignedInteger($column)->default(0);});
            }
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','recovery_generation'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->string('recovery_generation',64)->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','validation_generation'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->string('validation_generation',64)->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','last_recovery_at'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->timestamp('last_recovery_at')->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','expired_reported_at'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->timestamp('expired_reported_at')->nullable();});
            // Idempotent even after interrupted DDL. Never reset operational states.
            Capsule::statement('UPDATE mod_amssoft_fail2ban_rollups SET total_attempts=GREATEST(total_attempts,attempts), total_validation_attempts=GREATEST(total_validation_attempts,validation_attempts)');
            foreach(['ai_review_auto_recovery_enabled','ai_review_recovery_limit'] as $key)
                Database::setConfig($key,Database::getConfig($key,(string)Policy::fields()[$key][2]));
            foreach(['blocked_confirmed_at','blocked_until_check_at'] as $column)
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t)use($column){$t->timestamp($column)->nullable()->index();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','blocked_by_json'))
                Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->text('blocked_by_json')->nullable();});
            foreach(['ai_skip_effectively_banned','ai_blocked_recheck_seconds'] as $key)
                Database::setConfig($key,Database::getConfig($key,(string)Policy::fields()[$key][2]));
            foreach(['rollups','ai_suggestions','detections'] as $suffix)
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_'.$suffix,'family_key'))
                    Capsule::schema()->table('mod_amssoft_fail2ban_'.$suffix,function($t){$t->string('family_key',80)->nullable()->index();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections','validation_state'))
                Capsule::schema()->table('mod_amssoft_fail2ban_detections',function($t){$t->string('validation_state',16)->default('unknown')->index();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections','validated_at'))
                Capsule::schema()->table('mod_amssoft_fail2ban_detections',function($t){$t->timestamp('validated_at')->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_detections','validation_generation'))
                Capsule::schema()->table('mod_amssoft_fail2ban_detections',function($t){$t->string('validation_generation',64)->nullable();});
            foreach(['decision_code','executed_jail'] as $column)
                if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions',$column))
                    Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t)use($column){$t->string($column,80)->nullable();});
            if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions','promotion_result'))
                Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions',function($t){$t->text('promotion_result')->nullable();});
            if(!Capsule::schema()->hasTable('mod_amssoft_fail2ban_rules'))
                Capsule::schema()->create('mod_amssoft_fail2ban_rules',function($t){$t->char('scope_key',64)->primary();$t->string('family_key',80);$t->string('format',16);$t->string('filter_name',50);$t->string('jail',64);$t->text('sources');$t->longText('evidence');$t->timestamp('updated_at')->useCurrent();});
            foreach(['ai_auto_update_managed_filters','ai_filter_max_updates_per_day','ai_filter_update_cooldown_minutes','ai_filter_max_regex','ai_auto_max_managed_jails','ai_history_validation_per_cycle','ai_learning_sources'] as $key)
                Database::setConfig($key,Database::getConfig($key,(string)Policy::fields()[$key][2]));
            // Grouping metadata only: no revisions, statuses or attempts change.
            Capsule::table('mod_amssoft_fail2ban_rollups')->whereNull('family_key')->orderBy('id')->chunk(200,function($rows){
                foreach($rows as $row){$samples=json_decode($row->samples,true)?:[];$family=isset($samples[0]['line'])?AttackFamily::fromLine($samples[0]['line']):null;
                    if($family)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row->id)->whereNull('family_key')->update(['family_key'=>$family]);}
            });
            Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->whereNull('family_key')->orderBy('id')->chunk(200,function($rows){
                foreach($rows as $row)Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$row->id)->whereNull('family_key')->update(['family_key'=>AttackFamily::forSuggestion((array)$row)]);
            });
            EvidenceLinks::migrate();
            self::structuralColumns();
            DecisionMemory::migrate(); AnalysisWork::migrate();
            DecisionProtection::migrate();
            self::finish28();
            Database::setConfig('schema19_complete','1');
            Database::setConfig('schema20_complete','1');
            Database::setConfig('schema21_complete','1');
            Database::setConfig('schema22_complete','1');
            Database::setConfig('schema23_complete','1');
            Database::setConfig('schema24_complete','1');
        } finally {
            Capsule::selectOne("SELECT RELEASE_LOCK('amssoft_fail2ban_schema')");
        }
    }

    private static function finish28(): void
    {
        self::finish27();
        foreach(ProbeApplications::KEYS as $k)if(Database::getConfig($k,'')==='')Database::setConfig($k,(string)Policy::fields()[$k][2]);
        if(Database::getConfig('schema28_complete','0')!=='1'){
            $groups=preg_split('/\s+/',trim(Database::getConfig('native_probe_groups','')),-1,PREG_SPLIT_NO_EMPTY);
            if(!in_array('query_traversal',$groups,true))$groups[]='query_traversal';
            Database::setConfig('native_probe_groups',implode("\n",$groups));
        }
        Database::setConfig('schema_version','28');Database::setConfig('schema28_complete','1');
        self::finish29();
    }
    private static function finish29(): void
    {
        foreach(ProbeSimulation::KEYS as $key)if(Database::getConfig($key,null)===null)
            Database::setConfig($key,(string)Policy::fields()[$key][2]);
        Database::setConfig('schema_version','29');Database::setConfig('schema29_complete','1');
        self::finish30();
    }
    private static function finish30(): void
    {
        if(Database::getConfig('schema30_complete','0')!=='1'){
            $groups=preg_split('/\s+/',trim(Database::getConfig('ai_application_probe_groups','')),-1,PREG_SPLIT_NO_EMPTY);
            $legacy=ProbeApplications::LEGACY_GROUPS;sort($legacy,SORT_STRING);$selected=$groups;sort($selected,SORT_STRING);
            // Expand the old default only; an operator's custom selection is not consent.
            if($selected===$legacy)Database::setConfig('ai_application_probe_groups',implode("\n",ProbeApplications::GROUPS));
        }
        Database::setConfig('schema_version','30');Database::setConfig('schema30_complete','1');
        self::finish31();
    }
    private static function finish31(): void
    {
        foreach(array_merge(ApplicationWindow::KEYS,['autoindex_review_days','autoindex_review_lookback_hours']) as $key)
            if(Database::getConfig($key,null)===null)Database::setConfig($key,(string)Policy::fields()[$key][2]);
        Database::setConfig('schema_version','31');Database::setConfig('schema31_complete','1');
        self::finish32();
    }
    private static function finish32(): void
    {
        DashboardMetadata::migrate();
        Database::setConfig('schema_version','32');Database::setConfig('schema32_complete','1');
        self::finish33();
    }
    private static function finish33(): void
    {
        foreach(PhpScan::KEYS as $key)if(Database::getConfig($key,null)===null)
            Database::setConfig($key,(string)Policy::fields()[$key][2]);
        Database::setConfig('schema_version','33');Database::setConfig('schema33_complete','1');
        self::finish34();
    }
    private static function finish34(): void
    {
        // Configuration only: no DDL, history rewrite or native side effects.
        AnalysisPrompt::migrateKnownLegacy();
        Database::setConfig('schema_version','34');Database::setConfig('schema34_complete','1');
        self::finish35();
    }
    private static function finish35(): void
    {
        foreach(array_merge(CycleSchedule::KEYS,['ai_php_scan_history_enabled','ai_php_scan_history_rows']) as $key)
            if(Database::getConfig($key,null)===null)Database::setConfig($key,(string)Policy::fields()[$key][2]);
        Database::setConfig('schema_version','35');Database::setConfig('schema35_complete','1');
        self::finish36();
    }
    private static function finish36(): void
    {
        foreach(LocalObservation::KEYS as $key)if(Database::getConfig($key,null)===null)
            Database::setConfig($key,(string)Policy::fields()[$key][2]);
        Database::setConfig('schema_version','36');Database::setConfig('schema36_complete','1');
        self::finish37();
    }
    private static function finish37(): void
    {
        if(Database::getConfig(LocalObservation::HISTORY_KEY,null)===null)
            Database::setConfig(LocalObservation::HISTORY_KEY,(string)Policy::fields()[LocalObservation::HISTORY_KEY][2]);
        // Keep counters/history intact. The first metric-v2 cycle starts a new interval.
        Database::setConfig('schema_version','37');Database::setConfig('schema37_complete','1');
    }
    private static function finish27(): void
    {
        RecentActivity::migrate();
        foreach(['ai_analysis_recent_minutes','ai_individual_probe_enabled','ai_individual_probe_min_confidence',
            'ai_individual_probe_min_events','ai_individual_probe_min_targets','ai_individual_probe_window_minutes'] as $k)
            if(Database::getConfig($k,'')==='')Database::setConfig($k,(string)Policy::fields()[$k][2]);
        foreach(NativeProbes::KEYS as $k)if(Database::getConfig($k,'')==='')Database::setConfig($k,(string)Policy::fields()[$k][2]);
        if(Database::getConfig('schema27_complete','0')!=='1'){
            $groups=preg_split('/\s+/',trim(Database::getConfig('native_probe_groups','')),-1,PREG_SPLIT_NO_EMPTY);
            if(!in_array('traversal',$groups,true))$groups[]='traversal';
            Database::setConfig('native_probe_groups',implode("\n",$groups));
        }
        if(Database::getConfig('ai_non_offensive_paths','')==='')Database::setConfig('ai_non_offensive_paths',RequestEvidence::NORMAL_PATHS);
        Database::setConfig('schema_version','27');Database::setConfig('schema24_complete','1');Database::setConfig('schema25_complete','1');Database::setConfig('schema26_complete','1');Database::setConfig('schema27_complete','1');
    }

    private static function structuralColumns(): void
    {
        if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','behavior_variants'))
            Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->text('behavior_variants')->nullable();});
        if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','behavior_complete'))
            Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->boolean('behavior_complete')->default(false);});
    }
}
