<?php
/**
 * Engine integration contract, not a test of the real structural repositories.
 * Run: php tests/structural_engine.php [--whmcs-root=/var/www/html/whmcs]
 * Existing schema 22 SQL tables must exist and use InnoDB. Schema 23 is selected
 * only inside a rolled-back transaction; no migration/activation/DDL is called.
 * AnalysisWork/DecisionMemory are deliberately declared before Router autoload.
 *
 * Required interfaces:
 * AnalysisWork::nextBatch(): ?array {id,batch,proofs,contexts,raw}
 * ::consolidate(array): array (rows carry _work_refs id/revision pairs,
 * _work_snapshots originals and _work_events)
 * ::saveBatch(array,array,array,array): string; ::markItem(string,string): void
 * ::finalize(array,string): void; ::health(): array
 * DecisionMemory::reusable(array): bool; ::remember(array,array,int): void
 * ::invalidate(array): void
 * Finalization must CAS each captured reference revision independently.
 * This double uses BehaviorStore::acknowledge for real SQL CAS; production
 * AnalysisWork persistence/CAS needs its own repository integration suite.
 */
namespace AMS\Fail2Ban {
    use WHMCS\Database\Capsule as C;

    final class StructuralFixture
    {
        public static string $source;
        public static array $ids = [], $references = [], $trace = [], $failures = [], $metrics = [];
        public static ?string $racingReference = null;
        public static int $checks = 0;

        public static function check(bool $condition, string $message): void
        {
            self::$checks++;
            if (!$condition) self::$failures[] = $message;
        }

        public static function guard(): void
        {
            if (C::connection()->transactionLevel() !== 1) {
                throw new \RuntimeException('Fixture requires the outer rollback transaction');
            }
            self::check((int) C::selectOne("SELECT IS_USED_LOCK('amsfb_cycle') AS owner")->owner
                === (int) C::selectOne('SELECT CONNECTION_ID() AS id')->id, 'Cycle lock lost');
        }

        public static function beforeDecision(string $ip): void
        {
            self::guard();
            self::check(AnalysisWork::$checkpoint !== null, 'Decision occurred before saveBatch');
            self::$trace[] = 'decision:' . $ip;
        }
    }

    class Fail2BanClient
    {
        public array $bans = [], $confirmed = [];
        public function hasEffectiveBan($jail, $ip): bool { return isset($this->confirmed[$ip]); }
        public function banIP($jail, $ip): bool
        {
            StructuralFixture::beforeDecision($ip);
            StructuralFixture::check(!isset($this->confirmed[$ip]), 'Confirmed IP was banned again: ' . $ip);
            $this->bans[] = $ip;
            $this->confirmed[$ip] = true;
            return true;
        }
    }

    class Privileged
    {
        public static int $normalizations = 0;
        public static bool $interrupt = true;
        public static function run(array $args): array
        {
            StructuralFixture::guard();
            if ($args[0] === 'ban-coverage') return ['success'=>true, 'observed_at'=>time(), 'entries'=>[]];
            if ($args[0] === 'ensure-ai-jail') return ['success'=>true];
            if ($args[0] === 'normalize-filter') {
                $payload = json_decode(file_get_contents($args[1]), true, 512, JSON_THROW_ON_ERROR);
                StructuralFixture::beforeDecision(Safety::sourceIp($payload['evidence'][0]));
                if (self::$interrupt && ++self::$normalizations === 6) {
                    self::$interrupt = false;
                    throw new CycleBudgetExceeded('Fixture native deadline after five decisions');
                }
                return ['success'=>true, 'patterns'=>$payload['patterns'],
                    'matched_sha256'=>array_map(fn($line)=>hash('sha256', $line), $payload['evidence'])];
            }
            throw new \RuntimeException('Unexpected native operation: ' . $args[0]);
        }
    }

    class ManagedRules
    {
        public static bool $interrupt = true;
        public static function processRequest($client): array
        {
            // Force the OUTER budget catch too, exercising the finally snapshot.
            if (self::$interrupt) {
                self::$interrupt = false;
                throw new CycleBudgetExceeded('Fixture learning budget');
            }
            return [];
        }
        public static function enqueueAutomatic($suggestion): array
        {
            throw new \RuntimeException('Unexpected promotion in structural fixture');
        }
    }

    class DecisionMemory
    {
        public static array $reusable = [], $remembered = [];
        public static function reusable(array $row): bool { return isset(self::$reusable[$row['id']]); }
        public static function invalidate(array $row): void
        {
            StructuralFixture::$trace[] = 'invalidate:' . $row['id'];
        }
        public static function remember(array $row, array $item, int $id): void
        {
            StructuralFixture::beforeDecision($row['ip']);
            self::$remembered[$row['id']] = [$item, $id];
        }
    }

    class AnalysisWork
    {
        public static ?array $checkpoint = null;
        public static array $marked = [], $finalized = [];
        public static int $saves = 0, $replays = 0;
        public static function nextBatch(): ?array
        {
            if (self::$checkpoint === null || count(self::$marked) === count(self::$checkpoint['batch'])) return null;
            self::$replays++;
            $checkpoint = self::$checkpoint;
            $checkpoint['batch'] = array_values(array_filter($checkpoint['batch'],
                fn($row)=>!isset(self::$marked[$row['id']])));
            return $checkpoint;
        }
        public static function consolidate(array $rows): array
        {
            foreach ($rows as &$row) {
                $row['_work_refs'] = [['id'=>$row['id'], 'revision'=>(int)$row['revision']]];
                $row['_work_snapshots'] = [$row];
                $row['_work_events'] = BehaviorStore::proofEvents($row);
                foreach (StructuralFixture::$references[$row['id']] ?? [] as $id) {
                    $ref = (array) C::table('mod_amssoft_fail2ban_rollups')->where('id', $id)->first();
                    $row['_work_refs'][] = ['id'=>$ref['id'], 'revision'=>(int)$ref['revision']];
                    $row['_work_snapshots'][] = $ref;
                    $row['_work_events'] = array_merge($row['_work_events'], BehaviorStore::proofEvents($ref));
                }
            }
            unset($row);
            return $rows;
        }
        public static function saveBatch(array $batch, array $proofs, array $contexts, array $raw): string
        {
            StructuralFixture::guard();
            StructuralFixture::check(C::table('mod_amssoft_fail2ban_ai_suggestions')
                ->where('source_log', StructuralFixture::$source)->count() === 0, 'Suggestions saved before raw response');
            StructuralFixture::check(count($raw) === 10 && count($batch) === 10, 'Paid response was not saved whole');
            self::$saves++;
            $id = 'fixture-checkpoint';
            self::$checkpoint = compact('id', 'batch', 'proofs', 'contexts', 'raw');
            StructuralFixture::$trace[] = 'saved';
            // Deterministic collector interleaving after snapshot, before CAS.
            if (StructuralFixture::$racingReference !== null) {
                C::table('mod_amssoft_fail2ban_rollups')->where('id', StructuralFixture::$racingReference)
                    ->update(['revision'=>2, 'events'=>2, 'processing_state'=>'review', 'attempts'=>3,
                        'failure_code'=>'fixture_new_revision', 'retry_at'=>date('Y-m-d H:i:s', time()+3600)]);
            }
            return $id;
        }
        public static function finalize(array $row, string $reason): void
        {
            StructuralFixture::guard();
            self::$finalized[$row['id']] = $reason;
            $snapshots = array_column($row['_work_snapshots'] ?? [$row], null, 'id');
            foreach ($row['_work_refs'] ?? [['id'=>$row['id'], 'revision'=>$row['revision']]] as $ref) {
                $snapshot = $snapshots[$ref['id']] ?? null;
                if (!$snapshot || (int)$snapshot['revision'] !== (int)$ref['revision']) continue;
                $live = C::table('mod_amssoft_fail2ban_rollups')->where('id',$ref['id'])->lockForUpdate()->first();
                if (!$live || (int)$live->revision !== (int)$ref['revision']) continue;
                foreach (['ip','source_log','pattern','processing_state','retry_at','attempts','validation_attempts','failure_code','decision_state'] as $field) {
                    if (($live->$field ?? null) != ($snapshot[$field] ?? null)) continue 2;
                }
                BehaviorStore::acknowledge($snapshot);
            }
        }
        public static function markItem(string $id, string $task): void
        {
            StructuralFixture::check($id === 'fixture-checkpoint', 'Wrong checkpoint ID');
            self::$marked[$task] = true;
        }
        public static function health(): array
        {
            return ['unique_ready'=>BehaviorStore::health()['ready'],
                'pending_batches'=>self::$checkpoint !== null && count(self::$marked)<count(self::$checkpoint['batch']) ? 1 : 0,
                'pending_items'=>self::$checkpoint === null ? 0 : count(self::$checkpoint['batch'])-count(self::$marked)];
        }
    }
}

namespace {
    if (PHP_SAPI !== 'cli') exit(1);
    use AMS\Fail2Ban\{AIAnalyzer, AnalysisWork, AutoBanEngine, BehaviorStore, Database, DecisionMemory,
        Fail2BanClient, QueueTelemetry, StructuralFixture as F};
    use WHMCS\Database\Capsule as C;

    $root = '/var/www/html/whmcs';
    foreach (array_slice($argv, 1) as $arg) {
        if (!str_starts_with($arg, '--whmcs-root=')) throw new RuntimeException('Unknown argument: ' . $arg);
        $root = substr($arg, strlen('--whmcs-root='));
    }
    require $root . '/configuration.php';
    require $root . '/vendor/autoload.php';
    require dirname(__DIR__) . '/lib/Router.php';

    class StructuralFixtureAI extends AIAnalyzer
    {
        public int $calls = 0;
        public function analyzeSubjects(array $lines, array $context): array
        {
            $this->requestStarting();
            $this->calls++;
            F::$trace[] = 'api';
            $out = [];
            foreach ($context as $ip=>$value) {
                $out[] = ['ip'=>$ip, 'action'=>'ban', 'severity'=>'critical', 'confidence'=>99,
                    'threat'=>'fixture', 'evidence'=>array_values(array_filter($lines, fn($line)=>str_starts_with($line, $ip.' '))),
                    'filter_name'=>'fixture', 'failregex'=>'^<HOST> .*env'];
            }
            return $out;
        }
    }

    $capsule = new C;
    $capsule->addConnection(['driver'=>'mysql', 'host'=>$db_host, 'database'=>$db_name,
        'username'=>$db_username, 'password'=>$db_password, 'charset'=>'utf8mb4']);
    $capsule->setAsGlobal();
    $capsule->bootEloquent();
    $db = C::connection();
    // Fail closed before any writes if rollback cannot cover an existing table.
    $tables = $db->select('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES
        WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,21)=?', ['mod_amssoft_fail2ban_']);
    $available = [];
    foreach ($tables as $table) {
        if (strtoupper($table->engine ?? '') !== 'INNODB') throw new RuntimeException('Nontransactional module table: '.$table->name);
        $available[] = $table->name;
    }
    foreach (['config','rollups','ai_suggestions','detections','evidence_links','jobs','logs'] as $suffix) {
        if (!in_array('mod_amssoft_fail2ban_'.$suffix, $available, true)) {
            throw new RuntimeException('Missing existing table: '.$suffix.'; no migration will be run');
        }
    }
    if ((int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired")->acquired !== 1) throw new RuntimeException('Cycle busy; no writes made, retry after other SQL suites');
    $schemaBefore = Database::getConfig('schema_version');
    $transaction = false;
    try {
        $db->beginTransaction();
        $transaction = true;
        F::guard();
        if (C::table('mod_amssoft_fail2ban_jobs')->whereIn('status',['queued','running'])->exists()) {
            throw new RuntimeException('Maintenance job active; retry after it finishes');
        }
        C::table('mod_amssoft_fail2ban_rollups')->update(['analyzed_revision'=>C::raw('revision')]);
        foreach (['schema_version'=>'23','ai_auto_enabled'=>'1','ai_confirmed_auto'=>'1','ai_mode'=>'threshold',
            'ai_auto_create_filter'=>'0','ai_cycle_max_calls'=>'1','ai_cycle_seconds'=>'180',
            'ai_history_validation_per_cycle'=>'0','ai_review_auto_recovery_enabled'=>'0','ai_rule_requests'=>'{}',
            'ai_cycle_metrics'=>'[]','ai_whitelist_ips'=>'','ai_threshold_critical'=>'1:30',
            'ai_behavior_enabled'=>'0','ai_queue_urgent_enabled'=>'0','ai_auto_min_confidence'=>'90',
            'ai_filter_min_confidence'=>'90','ai_skip_effectively_banned'=>'0'] as $key=>$value) Database::setConfig($key,$value);
        F::$source = '/var/log/structural-access-fixture-'.bin2hex(random_bytes(8));
        $insert = static function(string $id, string $ip, string $pattern, string $bucket): void {
            $line = $ip.' - - ['.date('d/M/Y:H:i:s O').'] "GET /.env HTTP/1.1" 404 10 "-" "fixture"';
            $event = ['id'=>hash('sha256',$id.'event'),'ip'=>$ip,'line'=>$line,'time'=>time(),'pattern'=>$pattern];
            C::table('mod_amssoft_fail2ban_rollups')->insert(['id'=>$id,'ip'=>$ip,'source_log'=>F::$source,
                'pattern'=>$pattern,'family_key'=>'env-exposure','bucket'=>$bucket,'events'=>1,'revision'=>1,'samples'=>json_encode([$event])]);
        };
        $bucket = date('Y-m-d H:i:s',time()-60);
        for ($i=1; $i<=10; $i++) {
            $id = hash('sha256',F::$source.$i);
            F::$ids[] = $id;
            $insert($id,'198.18.32.'.$i,hash('sha256','pattern'.$i),$bucket);
        }
        // Both stable and concurrently advanced references belong to one subject.
        foreach (['stable','racing'] as $kind) {
            $id = hash('sha256',F::$source.$kind);
            F::$references[F::$ids[0]][] = $id;
            $insert($id,'198.18.32.1',hash('sha256','pattern1'),date('Y-m-d H:i:s',time()-30));
            if ($kind === 'racing') F::$racingReference = $id;
        }
        $ai = new StructuralFixtureAI('openai','fixture');
        $client = new Fail2BanClient;
        $engine = new AutoBanEngine($ai,$client);
        $first = $engine->runAnalysis();
        F::check(!isset($first['_locked_out']), 'First engine invocation locked out');
        F::check($ai->calls === 1 && AnalysisWork::$saves === 1, 'Expected one API call and one raw checkpoint');
        F::check(array_slice(F::$trace,0,2) === ['api','saved'], 'Raw response not checkpointed before processing');
        F::check(count($client->bans) === 5, 'Native interruption did not preserve exactly five confirmed bans');
        F::check(count(AnalysisWork::$marked) === 5, 'Interrupted checkpoint cursor lost completed items');
        F::check(C::table('mod_amssoft_fail2ban_rollups')->whereIn('id',F::$ids)
            ->whereColumn('analyzed_revision','>=','revision')->count() === 5, 'Partial acknowledgements lost');
        $metrics = QueueTelemetry::summary()['last'];
        F::$metrics['interrupted'] = $metrics;
        F::check(($metrics['error']??null) === '', 'Budget recorded as processing error: '.json_encode($metrics['error']??null));
        F::check(($metrics['reason']??null) === 'call_limit', 'Paid-call cap reason incorrect: '.json_encode($metrics['reason']??null));
        F::check(($metrics['budget_phase']??null) === 'processing', 'Native budget phase missing');
        F::check(($metrics['completed']??null) === 5, 'Partial cycle completion count wrong');
        F::check(isset($metrics['eligible_ready_end']) && is_int($metrics['eligible_ready_end'])
            && $metrics['eligible_ready_end'] === BehaviorStore::health()['ready'], 'Budget finally path did not measure eligible_ready_end');
        F::check(($metrics['work_health']['pending_items']??null) === 5, 'Checkpoint health missing from budget metrics');

        $confirmedBefore = $client->bans;
        $suggestionsBefore = C::table('mod_amssoft_fail2ban_ai_suggestions')->where('source_log',F::$source)->count();
        $engine->runAnalysis();
        F::check($ai->calls === 1 && AnalysisWork::$saves === 1, 'Replay charged another API call');
        F::check(AnalysisWork::$replays >= 1, 'Checkpoint never replayed');
        F::check(count($client->bans) === 10 && count(array_unique($client->bans)) === 10, 'Replay duplicated or lost a ban');
        F::check(array_slice($client->bans,0,5) === $confirmedBefore, 'Confirmed prefix changed during replay');
        F::check($suggestionsBefore === 5 && C::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('source_log',F::$source)->count() === 10, 'Replay duplicated or lost saved decisions');
        F::check(count(AnalysisWork::$marked) === 10, 'Replay failed to close all checkpoint items');
        F::check(C::table('mod_amssoft_fail2ban_rollups')->whereIn('id',F::$ids)
            ->whereColumn('analyzed_revision','>=','revision')->count() === 10, 'Replay left paid decisions incomplete');
        $metrics = QueueTelemetry::summary()['last'];
        F::$metrics['replay'] = $metrics;
        F::check(($metrics['calls']??null) === 0 && ($metrics['completed']??null) === 0, 'Replay inflated paid-call completion counters');
        F::check(($metrics['resumed']??null) === 5, 'Replay must count only the five unresolved decisions');
        F::check(($metrics['error']??null) === '', 'Replay produced processing error: '.json_encode($metrics['error']??null));
        F::check(($metrics['reason']??null) === 'local_work_completed'
            && ($metrics['stop_reason']??null) === 'local_work_completed', 'Zero-API replay completion reason incorrect');
        $stable = C::table('mod_amssoft_fail2ban_rollups')->where('id',F::$references[F::$ids[0]][0])->first();
        F::check((int)$stable->analyzed_revision === 1, 'Stable consolidated reference was not finalized');
        $racing = C::table('mod_amssoft_fail2ban_rollups')->where('id',F::$racingReference)->first();
        F::check((int)$racing->revision === 2 && (int)$racing->analyzed_revision === 0 && (int)$racing->events === 2
            && (int)$racing->attempts === 3 && $racing->processing_state === 'review'
            && $racing->failure_code === 'fixture_new_revision' && $racing->retry_at !== null,
            'CAS overwrote concurrent reference revision/backoff/review');
        $engine->runAnalysis();
        F::check($ai->calls === 1 && count($client->bans) === 10, 'Completed checkpoint reanalyzed or rebanned on third invocation');
        F::guard();
    } finally {
        try {
            if ($transaction) {
                if ($db->transactionLevel() !== 1) throw new RuntimeException('Outer transaction unexpectedly changed');
                $db->rollBack();
                F::check(Database::getConfig('schema_version') === $schemaBefore, 'Schema config escaped rollback');
                F::check(C::table('mod_amssoft_fail2ban_rollups')->where('source_log',F::$source ?? '')->count() === 0, 'Fixture rollups escaped rollback');
                F::check(C::table('mod_amssoft_fail2ban_ai_suggestions')->where('source_log',F::$source ?? '')->count() === 0, 'Fixture suggestions escaped rollback');
            }
        } finally { $db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')"); }
    }
    foreach (F::$metrics as $cycle=>$metrics) {
        echo $cycle.': '.json_encode(array_intersect_key($metrics,array_flip([
            'calls','completed','resumed','reused','error','reason','stop_reason','budget_stopped',
            'budget_phase','eligible_ready_end','measurement_error'])),JSON_UNESCAPED_SLASHES)."\n";
    }
    if (F::$failures) throw new RuntimeException("Structural engine assertions failed:\n- ".implode("\n- ",array_unique(F::$failures)));
    echo 'PASS: '.F::$checks." structural engine checks; SQL rolled back; fake API/native/bans/repositories; no DDL\n";
}
