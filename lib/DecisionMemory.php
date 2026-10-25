<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/AnalysisPrompt.php';

use WHMCS\Database\Capsule;

/**
 * Supported only: exact, complete standard combined access logs. Unknown,
 * error and auth formats fail closed. The collector's last-five sample is NOT
 * full coverage when events > count(samples), unless behavior_complete=1 and
 * behavior_variants contains the persistent full set (at most 16 hashes).
 * Only GET/HEAD and monitor/whitelist decisions are eligible; request
 * bodies are absent from access logs. The authenticated user token is retained.
 *
 * remember() is called only after a real API decision is durably saved, with
 * its _events, _task_id and _analysis_key. Main calls invalidate() for EVERY
 * fresh bound API decision, before remember/ban, even for low confidence or an
 * ineligible action. A cache hit must never call invalidate() or remember().
 * reusable() is read-only: main owns durable scheduling links/hit accounting and
 * must recheck policyFingerprint() at its commit checkpoint under its lock.
 */
final class DecisionMemory
{
    public const TABLE = 'mod_amssoft_fail2ban_decision_memory';
    private const VERSION = 'exact-access-get-head-complete-v2';
    private const DEFAULTS = [
        'ai_reuse_enabled'=>0, 'ai_reuse_min_confidence'=>95,
        'ai_reuse_minutes'=>30, 'ai_reuse_activity_multiplier'=>2,
        'ai_reuse_sample_percent'=>10,
    ];

    public static function enabled(): bool
    {
        return (int)Database::getConfig('schema_version','0') >= 23
            && (string)Database::getConfig('ai_reuse_enabled','0') === '1';
    }

    /** Called explicitly by the locked schema migration, never by a lookup. */
    public static function migrate(): void
    {
        if (Capsule::schema()->hasTable(self::TABLE)) return;
        Capsule::schema()->create(self::TABLE, static function($t) {
            $t->charset = 'utf8mb4'; $t->collation = 'utf8mb4_unicode_ci';
            $t->char('key',64)->primary(); $t->string('ip',45)->index();
            $t->string('source_log',500); $t->char('pattern',64);
            $t->char('signature',64); $t->char('policy_hash',64);
            $t->unsignedBigInteger('suggestion_id')->index();
            $t->unsignedInteger('confidence'); $t->unsignedInteger('baseline_events');
            $t->char('campaign_signature',64);
            $t->timestamp('valid_until')->index(); $t->timestamp('created_at');
        });
    }

    /** Bounded cleanup of this metadata only; original evidence is untouched. */
    public static function prune(): void
    {
        if ((int)Database::getConfig('schema_version','0')<23) return;
        $days = Policy::number('ai_evidence_retention_days');
        if ($days<1) return;
        Capsule::table(self::TABLE)->where('valid_until','<',date('Y-m-d H:i:s',time()-$days*86400))
            ->orderBy('valid_until')->limit(100)->delete();
    }

    /** Revoke only this subject's two normal-decision keys after fresh API work. */
    public static function invalidate(array $row): void
    {
        if ((int)Database::getConfig('schema_version','0')<23 || !self::subject($row)) return;
        Capsule::table(self::TABLE)->whereIn('key',[
            self::key($row,'monitor'),self::key($row,'whitelist'),
        ])->delete();
    }

    /** Hash the whole policy, not just reuse knobs; public for main checkpoints. */
    public static function policyFingerprint(): string
    {
        $values = Policy::values();
        // Observation-only controls must not invalidate paid-analysis memory.
        $values = array_filter($values,static fn($key)=>!str_starts_with($key,'ai_probe_simulation_')&&!str_starts_with($key,'autoindex_review_'),ARRAY_FILTER_USE_KEY);
        foreach (self::DEFAULTS as $key=>$default)
            $values[$key] = Database::getConfig($key,(string)($values[$key] ?? $default));
        return hash('sha256',json_encode(self::sorted([
            'version'=>self::VERSION, 'regex_generation'=>AIAnalyzer::RECOVERY_GENERATION,
            'analysis_contract'=>AnalysisPrompt::contract(),
            'values'=>$values,
        ]),JSON_THROW_ON_ERROR));
    }

    /** Complete access feature hash shared by collector and analysis workers. */
    public static function lineSignature(string $line,?string $ip=null): ?string
    {
        if (strlen($line)>65536 || preg_match('/[\x00-\x1f\x7f]/',$line)
            || preg_match('//u',$line)!==1 || AttackFamily::fromLine($line)!==null) return null;
        $quoted = '(?:[^"\\\\\x00-\x1f\x7f]|\\\\(?:["\\\\]|x[0-9A-Fa-f]{2}))*';
        $regex = '~\A(\S+ - \S+ )\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'
            .' ("(?:GET|HEAD) [^\x00-\x20"\\\\]+ HTTP/\d+\.\d+"'
            .' [1-5]\d{2} (?:\d+|-) "'.$quoted.'" "'.$quoted.'")\z~D';
        if (!preg_match($regex,$line,$m)) return null;
        $peer = explode(' ',$m[1],2)[0];
        if (Safety::canonicalIp($peer)!==$peer || ($ip!==null && $peer!==$ip)) return null;
        $date = \DateTimeImmutable::createFromFormat('!d/M/Y:H:i:s O',$m[2]);
        $errors = \DateTimeImmutable::getLastErrors();
        if (!$date || ($errors && ($errors['warning_count'] || $errors['error_count']))
            || $date->format('d/M/Y:H:i:s O')!==$m[2]) return null;
        return hash('sha256',$m[1].'[] '.$m[3]);
    }

    /** Full normalized variant SET, explicitly scoped to IP/source/pattern. */
    public static function signature(array $row): ?string
    {
        if (!self::subject($row) || self::knownAttackFamily($row)) return null;
        $samples = $row['samples'] ?? null;
        if (is_string($samples)) $samples = json_decode($samples,true);
        $events = self::positiveInt($row['events'] ?? null);
        if (!is_array($samples) || !array_is_list($samples) || !$samples || !$events
            || count($samples)>$events || !empty($row['truncated'])) return null;
        $complete = in_array($row['behavior_complete'] ?? null,[1,'1',true],true);
        $stored = null;
        if ($complete) {
            $stored = $row['behavior_variants'] ?? null;
            if (is_string($stored)) $stored = json_decode($stored,true);
            if (!is_array($stored) || !array_is_list($stored) || !$stored || count($stored)>16
                || count($stored)>$events) return null;
            foreach ($stored as $hash) if (!self::hex($hash)) return null;
            if (count(array_unique($stored))!==count($stored)) return null;
        } elseif (count($samples)!==$events) return null;
        $variants = []; $ids = [];
        foreach ($samples as $event) {
            if (!is_array($event) || ($event['ip'] ?? null) !== $row['ip']
                || ($event['pattern'] ?? null) !== $row['pattern']
                || (isset($event['source_log']) && $event['source_log'] !== $row['source_log'])
                || !self::hex($event['id'] ?? null) || isset($ids[$event['id']])
                || !empty($event['truncated']) || !is_string($event['line'] ?? null)) return null;
            $ids[$event['id']] = true;
            $line = $event['line'];
            $hash = self::lineSignature($line,$row['ip']);
            if ($hash===null || !self::positiveInt($event['time'] ?? null)
                || (int)$event['time'] !== BehaviorStore::eventTime($line)
                || BehaviorStore::pattern($line) !== $row['pattern']) return null;
            if ($stored!==null && !in_array($hash,$stored,true)) return null;
            $variants[$hash] = true;
        }
        $variants = $stored ?? array_keys($variants); sort($variants,SORT_STRING);
        if (count($variants)>16) return null;
        return hash('sha256',json_encode([$row['ip'],$row['source_log'],$row['pattern'],$variants],JSON_THROW_ON_ERROR));
    }

    public static function remember(array $row,array $item,int $suggestionId): void
    {
        if (!self::enabled() || $suggestionId<1 || !($settings=self::settings())
            || !($signature=self::signature($row))
            || !in_array($item['action'] ?? null,['monitor','whitelist'],true)
            || !self::hex($row['id'] ?? null) || !self::positiveInt($row['revision'] ?? null)
            || !self::positiveInt($item['confidence'] ?? null)
            || (int)$item['confidence']<$settings['ai_reuse_min_confidence']
            || (int)$item['confidence']>100 || self::knownAttackFamily($item)
            || ($item['ip'] ?? null)!==$row['ip'] || ($item['source_log'] ?? null)!==$row['source_log']
            || ($item['_pattern'] ?? null)!==$row['pattern']
            || ($item['_task_id'] ?? null)!==($row['id'] ?? null)
            || !self::hex($item['_analysis_key'] ?? null)
            || !is_array($item['_events'] ?? null) || !$item['_events'] || count($item['_events'])>8) return;
        $proofRow = $row;
        unset($proofRow['behavior_complete'],$proofRow['behavior_variants']);
        $proofRow['samples'] = $item['_events']; $proofRow['events'] = count($item['_events']);
        if (self::signature($proofRow)!==$signature) return;
        $evidence = $item['evidence'] ?? null;
        if (is_string($evidence)) $evidence = json_decode($evidence,true);
        if (!is_array($evidence) || !$evidence || !array_is_list($evidence)) return;
        $proofLines = array_column($item['_events'],'line'); $cited = [];
        foreach ($evidence as $line) {
            if (!is_string($line) || !in_array($line,$proofLines,true)
                || !($hash=self::lineSignature($line,$row['ip']))) return;
            $cited[$hash] = true;
        }
        $proved = [];
        foreach ($proofLines as $line) {
            $hash=self::lineSignature($line,$row['ip']);
            if ($hash===null) return;
            $proved[$hash] = true;
        }
        if (array_diff_key($proved,$cited)) return;
        $live = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$suggestionId)->first();
        if (!self::live($live,$row,$settings) || $live->classification!==$item['action']
            || (int)$live->confidence!==(int)$item['confidence']
            || ($live->analysis_key ?? null)!==$item['_analysis_key']
            || ($live->task_id ?? null)!==$item['_task_id']) return;
        $now = time(); $policy = self::policyFingerprint();
        $baseline = self::activity($row,$signature,$now,$now);
        if (!$baseline || $baseline>4294967295) return;
        $campaign = BehaviorStore::campaignSignature($row['source_log'],$row['pattern']);
        if (!self::hex($campaign)) return;
        // Only a fresh API decision may overwrite/renew this record.
        $values=[
            'ip'=>$row['ip'],'source_log'=>$row['source_log'],'pattern'=>$row['pattern'],
            'signature'=>$signature,'policy_hash'=>$policy,'suggestion_id'=>$suggestionId,
            'confidence'=>(int)$item['confidence'],'baseline_events'=>$baseline,
            'campaign_signature'=>$campaign,'created_at'=>date('Y-m-d H:i:s',$now),
            'valid_until'=>date('Y-m-d H:i:s',$now+$settings['ai_reuse_minutes']*60),
        ];
        Capsule::connection()->transaction(static function()use($row,$item,$values) {
            // Direct callers also cannot retain the opposite classification.
            $other=$item['action']==='monitor'?'whitelist':'monitor';
            Capsule::table(self::TABLE)->where('key',self::key($row,$other))->delete();
            Capsule::table(self::TABLE)->updateOrInsert(['key'=>self::key($row,$item['action'])],$values);
        });
    }

    public static function reusable(array $row): bool
    {
        try {
            if (!self::enabled() || !($settings=self::settings()) || !($signature=self::signature($row))
                || !self::hex($row['id'] ?? null) || !self::positiveInt($row['revision'] ?? null)) return false;
            $memory = Capsule::table(self::TABLE)->whereIn('key',[
                self::key($row,'monitor'),self::key($row,'whitelist'),
            ])->orderByDesc('created_at')->orderByDesc('suggestion_id')->first();
            if (!$memory) return false;
            $now = time(); $created = self::timestamp($memory->created_at ?? null);
            $until = self::timestamp($memory->valid_until ?? null);
            if (!$created || !$until || $created>$now || $until<=$now
                || $until>$created+$settings['ai_reuse_minutes']*60
                || $memory->ip!==$row['ip'] || $memory->source_log!==$row['source_log']
                || $memory->pattern!==$row['pattern'] || $memory->signature!==$signature
                || $memory->policy_hash!==self::policyFingerprint()
                || !self::positiveInt($memory->baseline_events ?? null)) return false;
            $live = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('id',$memory->suggestion_id)->first();
            if (!self::live($live,$row,$settings) || self::key($row,$live->classification)!==$memory->key
                || (int)$live->confidence!==(int)$memory->confidence) return false;
            if ($memory->campaign_signature!==BehaviorStore::campaignSignature($row['source_log'],$row['pattern'])) return false;
            $events = self::activity($row,$signature,$created,$now);
            if ($events===null || $events<(int)$memory->baseline_events
                || $events>=(int)$memory->baseline_events*$settings['ai_reuse_activity_multiplier']) return false;
            // Revision never enters sampling: collecting again cannot reroll.
            // Both row bucket and a fixed TTL-sized wall-clock window bind it.
            $bucket = self::timestamp($row['bucket'] ?? null);
            if (!$bucket || $bucket>$now || $bucket%600!==0) return false;
            $window = intdiv($now,$settings['ai_reuse_minutes']*60);
            $sample = hexdec(substr(hash('sha256',$memory->key."\0".$row['bucket']."\0".$window),0,8))%100;
            return $sample >= $settings['ai_reuse_sample_percent'];
        } catch (\Throwable $e) {
            // Missing schema, unreadable collaborators or corrupt data are misses.
            return false;
        }
    }

    /** Original 24h baseline + all arrivals until now; cutoff NEVER slides on hit.
     * Buckets are 10 minutes: include the intersecting boundary conservatively.
     * Every original subject must retain every event, including earlier variants.
     */
    private static function activity(array $row,string $signature,int $created,int $now): ?int
    {
        $from = (int)(floor(($created-86400)/600)*600);
        $rows = Capsule::table('mod_amssoft_fail2ban_rollups')->where('ip',$row['ip'])
            ->where('source_log',$row['source_log'])->where('pattern',$row['pattern'])
            ->where('bucket','>=',date('Y-m-d H:i:s',$from))
            ->where('bucket','<=',date('Y-m-d H:i:s',$now))->get();
        $events = 0; $found = false; $variants = [];
        foreach ($rows as $subject) {
            $subject = (array)$subject;
            if (self::signature($subject)===null) return null;
            $samples = is_string($subject['samples']) ? json_decode($subject['samples'],true) : $subject['samples'];
            if (in_array($subject['behavior_complete'] ?? null,[1,'1',true],true)) {
                $hashes = $subject['behavior_variants'];
                if (is_string($hashes)) $hashes = json_decode($hashes,true);
            } else $hashes = array_map(static fn($e)=>self::lineSignature($e['line'],$row['ip']),$samples);
            foreach ($hashes as $hash) $variants[$hash] = true;
            if (($subject['id'] ?? null)===($row['id'] ?? null)) {
                if ((int)($subject['revision'] ?? 0)!==(int)($row['revision'] ?? 0)
                    || (int)$subject['events']!==(int)$row['events']) return null;
                $found = true;
            }
            $events += (int)$subject['events'];
        }
        $variants = array_keys($variants); sort($variants,SORT_STRING);
        $aggregate = hash('sha256',json_encode([$row['ip'],$row['source_log'],$row['pattern'],$variants],JSON_THROW_ON_ERROR));
        return $found && $events>0 && $aggregate===$signature ? $events : null;
    }

    private static function live($live,array $row,array $settings): bool
    {
        return $live && $live->ip===$row['ip'] && $live->source_log===$row['source_log']
            && $live->pattern===$row['pattern'] && $live->status==='pending'
            && in_array($live->classification,['monitor','whitelist'],true)
            && self::positiveInt($live->confidence ?? null)
            && (int)$live->confidence >= $settings['ai_reuse_min_confidence']
            && (int)$live->confidence<=100 && !self::knownAttackFamily((array)$live);
    }

    private static function subject(array $row): bool
    {
        return is_string($row['ip'] ?? null) && Safety::canonicalIp($row['ip'])===$row['ip']
            && is_string($row['source_log'] ?? null) && strlen($row['source_log'])<=500
            && str_starts_with($row['source_log'],'/var/log/')
            && !preg_match('~[\x00-\x20]|(?:^|/)\.\.(?:/|$)~',$row['source_log'])
            && AttackFamily::format($row['source_log'])==='access' && self::hex($row['pattern'] ?? null);
    }

    private static function knownAttackFamily(array $row): bool
    {
        $family = $row['family_key'] ?? null;
        return $family!==null && $family!=='' && $family!=='pattern:'.($row['pattern'] ?? $row['_pattern'] ?? '');
    }

    private static function key(array $row,string $action): string
    {
        return hash('sha256',implode("\0",[$row['ip'],$row['source_log'],$row['pattern'],$action]));
    }

    private static function settings(): ?array
    {
        $result = [];
        foreach (self::DEFAULTS as $key=>$default) {
            $raw = Database::getConfig($key,(string)$default);
            if (!is_scalar($raw) || !preg_match('/^\d{1,6}$/D',(string)$raw)) return null;
            $result[$key] = (int)$raw;
        }
        if ($result['ai_reuse_min_confidence']<90 || $result['ai_reuse_min_confidence']>100
            || $result['ai_reuse_minutes']<5 || $result['ai_reuse_minutes']>240
            || $result['ai_reuse_activity_multiplier']<2 || $result['ai_reuse_activity_multiplier']>10
            || $result['ai_reuse_sample_percent']<1 || $result['ai_reuse_sample_percent']>100) return null;
        return $result;
    }

    private static function positiveInt($value): ?int
    {
        return (is_int($value) || is_string($value)) && preg_match('/^[1-9]\d{0,9}$/D',(string)$value)
            ? (int)$value : null;
    }

    private static function hex($value): bool
    {
        return is_string($value) && preg_match('/^[a-f0-9]{64}$/D',$value)===1;
    }

    private static function timestamp($value): ?int
    {
        if (!is_string($value)) return null;
        $date = \DateTimeImmutable::createFromFormat('!Y-m-d H:i:s',$value);
        return $date && $date->format('Y-m-d H:i:s')===$value ? $date->getTimestamp() : null;
    }

    private static function sorted(array $values): array
    {
        if (!array_is_list($values)) ksort($values,SORT_STRING);
        foreach ($values as &$value) if (is_array($value)) $value = self::sorted($value);
        return $values;
    }
}
