<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;
use Illuminate\Support\Collection;

class Database
{
    // -----------------------------------------------------------------------
    // Event logging
    // -----------------------------------------------------------------------

    public static function logEvent(
        string  $ip,
        string  $jail,
        string  $action,
        ?string $reason,
        ?int    $adminId
    ): void {
        Capsule::table('mod_amssoft_fail2ban_logs')->insert([
            'ip'        => $ip,
            'jail'      => $jail,
            'action'    => $action,
            'reason'    => $reason,
            'admin_id'  => $adminId,
            'timestamp' => Capsule::raw('NOW()'),
        ]);
    }

    // -----------------------------------------------------------------------
    // Queries — dashboard KPIs
    // -----------------------------------------------------------------------

    /** Returns all ban/manual_ban rows in the last N hours (newest first). */
    public static function getRecentBans(int $hours = 24): array
    {
        // [SEC-14] Evitar Capsule::raw() com variável interpolada — calcular timestamp em PHP.
        $since = date('Y-m-d H:i:s', time() - $hours * 3600);
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->where('timestamp', '>=', $since)
            ->whereIn('action', ['ban', 'manual_ban'])
            ->orderBy('timestamp', 'desc')
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();
    }

    /** Returns [['ip' => '...', 'count' => N], ...] sorted by count desc. */
    public static function getTopBannedIps(int $limit = 10): array
    {
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->select('ip', Capsule::raw('COUNT(*) AS `count`'))
            ->whereIn('action', ['ban', 'manual_ban'])
            ->groupBy('ip')
            ->orderByRaw('COUNT(*) DESC')
            ->limit($limit)
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();
    }

    /** Returns [['date' => 'Y-m-d', 'count' => N], ...] for the last N days. */
    public static function getBansSeries(int $days = 7): array
    {
        // [SEC-14] Evitar Capsule::raw() com variável interpolada.
        $since = date('Y-m-d H:i:s', time() - $days * 86400);
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->select(
                Capsule::raw('DATE(timestamp) AS `date`'),
                Capsule::raw('COUNT(*) AS `count`')
            )
            ->whereIn('action', ['ban', 'manual_ban'])
            ->where('timestamp', '>=', $since)
            ->groupBy(Capsule::raw('DATE(timestamp)'))
            ->orderBy(Capsule::raw('DATE(timestamp)'), 'asc')
            ->get()
            ->map(fn ($r) => ['date' => $r->date, 'count' => (int)$r->count])
            ->all();
    }

    /**
     * Conta jails auto-criados hoje (via logEvent com action='jail_created').
     * Usado para badge no dashboard.
     */
    public static function countAutoCreatedJailsToday(): int
    {
        $today = date('Y-m-d');
        return (int) Capsule::table('mod_amssoft_fail2ban_logs')
            ->where('action', 'jail_created')
            ->where('timestamp', '>=', $today . ' 00:00:00')
            ->count();
    }

    /**
     * Retorna os últimos eventos de auto-criação de jail.
     * Usado para exibir detalhes no dashboard.
     */
    public static function getRecentAutoCreatedJails(int $limit = 5): array
    {
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->where('action', 'jail_created')
            ->orderBy('timestamp', 'desc')
            ->limit($limit)
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();
    }

    // -----------------------------------------------------------------------
    // Queries — reports / history
    // -----------------------------------------------------------------------

    /**
     * Filters: date_from (Y-m-d), date_to (Y-m-d), ip (partial), jail, action.
     */
    public static function searchHistory(array $filters): Collection
    {
        $q = Capsule::table('mod_amssoft_fail2ban_logs')
            ->orderBy('timestamp', 'desc');

        if (!empty($filters['date_from'])) {
            $q->where('timestamp', '>=', $filters['date_from'] . ' 00:00:00');
        }
        if (!empty($filters['date_to'])) {
            $q->where('timestamp', '<=', $filters['date_to'] . ' 23:59:59');
        }
        if (!empty($filters['ip'])) {
            // [SEC-5] Escape SQL LIKE wildcards so that a literal "%" or "_" in the IP
            // value does not expand into a broad match. sanitizeIp() already ensures only
            // valid IPs reach here, but this guard is retained for future reuse safety.
            $safeIp = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $filters['ip']);
            $q->where('ip', 'like', '%' . $safeIp . '%');
        }
        if (!empty($filters['jail'])) {
            $q->where('jail', $filters['jail']);
        }
        if (!empty($filters['action'])) {
            $q->where('action', $filters['action']);
        }

        return $q->get()->map(fn ($r) => (array)$r);
    }

    /** Paginated version — returns ['data' => [...], 'total' => N, 'pages' => N]. */
    public static function searchHistoryPaged(array $filters, int $page = 1, int $perPage = 50): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_logs')
            ->orderBy('timestamp', 'desc');

        if (!empty($filters['date_from'])) {
            $q->where('timestamp', '>=', $filters['date_from'] . ' 00:00:00');
        }
        if (!empty($filters['date_to'])) {
            $q->where('timestamp', '<=', $filters['date_to'] . ' 23:59:59');
        }
        if (!empty($filters['ip'])) {
            // [SEC-5] Escape SQL LIKE wildcards (mirrors searchHistory fix).
            $safeIp = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $filters['ip']);
            $q->where('ip', 'like', '%' . $safeIp . '%');
        }
        if (!empty($filters['jail'])) {
            $q->where('jail', $filters['jail']);
        }
        if (!empty($filters['action'])) {
            $q->where('action', $filters['action']);
        }

        $total  = $q->count();
        $offset = ($page - 1) * $perPage;
        $data   = $q->offset($offset)->limit($perPage)->get()->map(fn ($r) => (array)$r)->all();

        return [
            'data'  => $data,
            'total' => $total,
            'pages' => (int)ceil($total / $perPage),
            'page'  => $page,
        ];
    }

    /** Return all distinct jails present in the log table. */
    public static function getKnownJails(): array
    {
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->distinct()
            ->orderBy('jail')
            ->pluck('jail')
            ->all();
    }

    // -----------------------------------------------------------------------
    // Key-value config store
    // -----------------------------------------------------------------------

    public static function getConfig(string $key, $default = null)
    {
        $row = Capsule::table('mod_amssoft_fail2ban_config')
            ->where('key', $key)
            ->first();
        return $row ? $row->value : $default;
    }

    public static function setConfig(string $key, $value): void
    {
        Capsule::table('mod_amssoft_fail2ban_config')
            ->updateOrInsert(['key' => $key], ['value' => $value]);
    }

    /**
     * Incrementa atomicamente um valor numérico na config (UPDATE value = value + 1).
     * Se a chave não existir, cria com valor 1.
     * Retorna o novo valor após o incremento.
     *
     * Usado para contadores onde read-then-write causaria perda em concorrência.
     */
    public static function incrementConfig(string $key): int
    {
        $exists = Capsule::table('mod_amssoft_fail2ban_config')
            ->where('key', $key)
            ->exists();

        if (!$exists) {
            Capsule::table('mod_amssoft_fail2ban_config')
                ->insert(['key' => $key, 'value' => '1']);
            return 1;
        }

        Capsule::table('mod_amssoft_fail2ban_config')
            ->where('key', $key)
            ->update(['value' => Capsule::raw('CAST(`value` AS UNSIGNED) + 1')]);

        return (int) self::getConfig($key, '1');
    }

    // -----------------------------------------------------------------------
    // Batch session helpers (processar log até esgotar)
    // -----------------------------------------------------------------------

    /**
     * Lê e decodifica o JSON da sessão de batch para um log.
     * Retorna null se a sessão não existir ou for JSON inválido.
     */
    public static function getBatchSession(string $logPath): ?array
    {
        $key = 'ai_batch_session_' . md5($logPath);
        $raw = self::getConfig($key, null);
        if ($raw === null) {
            return null;
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Cria ou reseta a sessão de batch para um log.
     * Owner é informativo (debug/rastreabilidade), não participa do gate.
     * BatchToken é o identificador de continuação (único por execução do loop).
     */
    public static function setBatchSession(string $logPath, string $owner, int $batches = 0, string $batchToken = ''): void
    {
        $key = 'ai_batch_session_' . md5($logPath);
        $data = [
            'owner'       => $owner,
            'started'     => time(),
            'heartbeat'   => time(),
            'batches'     => $batches,
            'batch_token' => $batchToken,
        ];
        self::setConfig($key, json_encode($data));
    }

    /**
     * Remove a sessão de batch (cleanup após conclusão ou timeout).
     */
    public static function clearBatchSession(string $logPath): void
    {
        $key = 'ai_batch_session_' . md5($logPath);
        Capsule::table('mod_amssoft_fail2ban_config')
            ->where('key', $key)
            ->delete();
    }

    /**
     * Incrementa o contador de batches na sessão (ler → incrementar → escrever).
     * Operação read-modify-write — segura porque roda dentro de uma sessão
     * que já foi adquirida via LogLock (outro processo pulou este log).
     * Retorna o novo valor de batches.
     */
    public static function incrementBatchSessionBatches(string $logPath): int
    {
        $session = self::getBatchSession($logPath);
        if ($session === null) {
            return 0;
        }
        $session['batches'] = ($session['batches'] ?? 0) + 1;
        $session['heartbeat'] = time();
        $key = 'ai_batch_session_' . md5($logPath);
        self::setConfig($key, json_encode($session));
        return $session['batches'];
    }

    /**
     * Atualiza apenas o heartbeat da sessão (mantém owner/batches intactos).
     */
    public static function updateBatchSessionHeartbeat(string $logPath): void
    {
        $session = self::getBatchSession($logPath);
        if ($session === null) {
            return;
        }
        $session['heartbeat'] = time();
        $key = 'ai_batch_session_' . md5($logPath);
        self::setConfig($key, json_encode($session));
    }

    // -----------------------------------------------------------------------
    // Sugestões da IA
    // -----------------------------------------------------------------------

    /** Salva uma nova sugestão da IA e retorna o ID inserido. */
    public static function saveSuggestion(array $data): int
    {
        // Upsert: se já existe sugestão pending para o mesmo IP, não duplica
        // Match por IP (não IP+jail) — consistente com autoDismissDuplicates()
        // que dispensa por IP ao aprovar. Mesmo IP em jails diferentes = mesmo atacante.
        $existing = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('ip',     $data['ip'] ?? '')
            ->where('status', 'pending')
            ->first();

        if ($existing) {
            return (int)$existing->id;
        }

        return (int) Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->insertGetId([
            'ip'             => $data['ip']             ?? '',
            'jail'           => $data['jail']           ?? '',
            'threat'         => $data['threat']         ?? '',
            'severity'       => in_array($data['severity'] ?? '', ['low', 'medium', 'high', 'critical'], true)
                                    ? $data['severity']
                                    : 'medium',
            'confidence'     => (int)($data['confidence'] ?? 0),
            'evidence'       => isset($data['evidence']) ? json_encode($data['evidence']) : null,
            'suggested_rule' => $data['suggested_rule'] ?? null,
            'reason'         => $data['reason']         ?? null,
            'bantime'        => (int)($data['bantime']  ?? 3600),
            'status'         => $data['status']         ?? 'pending',
            'created_at'     => Capsule::raw('NOW()'),
            // v3: filtro fail2ban gerado pela IA
            'filter_name'    => isset($data['filter_name']) && $data['filter_name'] !== ''
                                    ? substr(preg_replace('/[^a-z0-9-]/', '', strtolower($data['filter_name'])), 0, 64)
                                    : null,
            'failregex'      => isset($data['failregex']) && $data['failregex'] !== ''
                                    ? substr($data['failregex'], 0, 1000)
                                    : null,
            'source_log'     => isset($data['source_log']) && $data['source_log'] !== ''
                                    ? substr($data['source_log'], 0, 500)
                                    : null,
        ]);
    }

    /** Retorna todas as sugestões com status 'pending'. */
    public static function getPendingSuggestions(): array
    {
        return Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('status', 'pending')
            ->orderBy('created_at', 'desc')
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();
    }

    /** Retorna sugestões 'pending' paginadas. */
    public static function getPendingSuggestionsPaged(int $page = 1, int $perPage = 10): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('status', 'pending')
            ->orderBy('created_at', 'desc');

        $total  = $q->count();
        $pages  = $total > 0 ? (int)ceil($total / $perPage) : 1;
        $page   = max(1, min($page, $pages));
        $offset = ($page - 1) * $perPage;
        $data   = $q->offset($offset)->limit($perPage)->get()->map(fn ($r) => (array)$r)->all();

        return [
            'data'  => $data,
            'total' => $total,
            'pages' => $pages,
            'page'  => $page,
        ];
    }

    /** Retorna sugestões filtradas (para histórico). */
    public static function getAllSuggestions(array $filters = []): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->orderBy('created_at', 'desc');

        if (!empty($filters['status'])) {
            $q->where('status', $filters['status']);
        }
        if (!empty($filters['severity'])) {
            $q->where('severity', $filters['severity']);
        }
        if (!empty($filters['date_from'])) {
            $q->where('created_at', '>=', $filters['date_from'] . ' 00:00:00');
        }
        if (!empty($filters['date_to'])) {
            $q->where('created_at', '<=', $filters['date_to'] . ' 23:59:59');
        }

        return $q->get()->map(fn ($r) => (array)$r)->all();
    }

    /** Retorna sugestões filtradas paginadas (para histórico). */
    public static function getAllSuggestionsPaged(array $filters = [], int $page = 1, int $perPage = 10): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->orderBy('created_at', 'desc');

        if (!empty($filters['status'])) {
            $q->where('status', $filters['status']);
        }
        if (!empty($filters['severity'])) {
            $q->where('severity', $filters['severity']);
        }
        if (!empty($filters['date_from'])) {
            $q->where('created_at', '>=', $filters['date_from'] . ' 00:00:00');
        }
        if (!empty($filters['date_to'])) {
            $q->where('created_at', '<=', $filters['date_to'] . ' 23:59:59');
        }

        $total  = $q->count();
        $pages  = $total > 0 ? (int)ceil($total / $perPage) : 1;
        $page   = max(1, min($page, $pages));
        $offset = ($page - 1) * $perPage;
        $data   = $q->offset($offset)->limit($perPage)->get()->map(fn ($r) => (array)$r)->all();

        return [
            'data'  => $data,
            'total' => $total,
            'pages' => $pages,
            'page'  => $page,
        ];
    }

    /** Conta sugestões pendentes (para o card do dashboard). */
    public static function countPendingSuggestions(): int
    {
        return (int) Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('status', 'pending')
            ->count();
    }

    /** Retorna a sugestão mais recente (qualquer status). */
    public static function getLastSuggestion(): ?array
    {
        $row = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->orderBy('created_at', 'desc')
            ->first();
        return $row ? (array)$row : null;
    }

    /** Retorna uma sugestão por ID. */
    public static function getSuggestion(int $id): ?array
    {
        $row = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('id', $id)
            ->first();
        return $row ? (array)$row : null;
    }

    /**
     * Marca como 'approved' todas as sugestões pending do mesmo IP (exceto $excludeId).
     * Usado para dispensar duplicatas automaticamente ao aprovar uma sugestão.
     * Retorna array com os IDs dispensados.
     */
    public static function autoDismissDuplicates(string $ip, int $excludeId, int $adminId): array
    {
        $ids = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('ip', $ip)
            ->where('status', 'pending')
            ->where('id', '!=', $excludeId)
            ->pluck('id')
            ->toArray();

        if (!empty($ids)) {
            Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
                ->whereIn('id', $ids)
                ->update([
                    'status'      => 'approved',
                    'resolved_at' => Capsule::raw('NOW()'),
                    'resolved_by' => $adminId,
                ]);
        }
        return array_map('intval', $ids);
    }

    /** Atualiza o status de uma sugestão. */
    public static function updateSuggestionStatus(int $id, string $status, ?int $resolvedBy = null): bool
    {
        // [SEC-15] Validar status contra o ENUM antes de enviar ao banco.
        $allowed = ['pending', 'approved', 'rejected', 'auto_executed'];
        if (!in_array($status, $allowed, true)) {
            return false;
        }

        $affected = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('id', $id)
            ->update([
                'status'      => $status,
                'resolved_at' => Capsule::raw('NOW()'),
                'resolved_by' => $resolvedBy,
            ]);
        return $affected > 0;
    }

    /**
     * Retorna IPs que já possuem sugestão recente com status pending, approved
     * ou auto_executed (últimos $days dias). Usado para deduplicação antes de
     * chamar a API de IA — evita re-enviar o mesmo IP repetidamente.
     *
     * IPs com status 'rejected' são intencionalmente omitidos: se o admin
     * rejeitou e o IP continua atacando, ele deve ser re-analisado.
     */
    public static function getKnownIPs(int $days = 7): array
    {
        $since = date('Y-m-d H:i:s', time() - $days * 86400);
        return Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->whereIn('status', ['pending', 'approved', 'auto_executed'])
            ->where('created_at', '>=', $since)
            ->distinct()
            ->pluck('ip')
            ->map(fn ($ip) => (string)$ip)
            ->toArray();
    }

    /**
     * Retorna IPs com sugestão pendente (aguardando revisão do admin).
     * Usado para deduplicação em tempo real: evita floodar a fila com
     * o mesmo IP enquanto o admin ainda não agiu.
     */
    public static function getPendingIPs(): array
    {
        return Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('status', 'pending')
            ->distinct()
            ->pluck('ip')
            ->map(fn ($ip) => (string)$ip)
            ->toArray();
    }

    /**
     * Retorna sugestões pendentes agrupadas por país (JOIN com geo_cache).
     * IPs sem dados geo ou com country_code nulo/vazio ficam no grupo "Desconhecido".
     *
     * @return array [{country_code: string, country: string, ip_count: int}, ...]
     */
    public static function getPendingGroupedByCountry(): array
    {
        return Capsule::table('mod_amssoft_fail2ban_ai_suggestions as s')
            ->leftJoin('mod_amssoft_fail2ban_geo_cache as g', 's.ip', '=', 'g.ip')
            ->select(
                Capsule::raw("COALESCE(g.country_code, '') as country_code"),
                Capsule::raw("COALESCE(NULLIF(g.country, ''), 'Desconhecido') as country"),
                Capsule::raw('COUNT(*) as ip_count')
            )
            ->where('s.status', 'pending')
            ->groupBy(Capsule::raw("COALESCE(g.country_code, '')"), Capsule::raw("COALESCE(NULLIF(g.country, ''), 'Desconhecido')"))
            ->orderByRaw('COUNT(*) DESC')
            ->get()
            ->map(fn ($r) => [
                'country_code' => (string) $r->country_code,
                'country'      => (string) $r->country,
                'ip_count'     => (int) $r->ip_count,
            ])
            ->all();
    }

    /**
     * Retorna IDs de sugestões pendentes de um país específico.
     * country_code vazio = IPs sem dados geo (não estão no geo_cache ou country_code nulo/vazio).
     *
     * @param string $countryCode ISO 3166-1 alpha-2 ou vazio para "Desconhecido"
     * @return int[] IDs das sugestões
     */
    public static function getPendingIdsByCountry(string $countryCode): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_ai_suggestions as s')
            ->leftJoin('mod_amssoft_fail2ban_geo_cache as g', 's.ip', '=', 'g.ip')
            ->where('s.status', 'pending');

        if ($countryCode !== '') {
            $q->where('g.country_code', $countryCode);
        } else {
            $q->where(function ($sub) {
                $sub->whereNull('g.ip')
                    ->orWhereNull('g.country_code')
                    ->orWhere('g.country_code', '');
            });
        }

        return $q->pluck('s.id')
            ->map(fn ($id) => (int) $id)
            ->toArray();
    }

    /**
     * Conta detecções de um IP nas últimas X minutos (para modo threshold).
     * Considera sugestões com status pending ou auto_executed.
     */
    public static function countRecentDetections(string $ip, int $minutes): int
    {
        // [SEC-14] Evitar Capsule::raw() com variável interpolada.
        $since = date('Y-m-d H:i:s', time() - $minutes * 60);
        return (int) Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('ip', $ip)
            ->whereIn('status', ['pending', 'auto_executed'])
            ->where('created_at', '>=', $since)
            ->count();
    }

    // -----------------------------------------------------------------------
    // Cross-reference de IPs banidos
    // -----------------------------------------------------------------------

    /**
     * Marca o filtro fail2ban como criado para a sugestão.
     * Não altera status nem resolved_at — a sugestão continua pending
     * para que o admin ainda possa usar "Banir IP" independentemente.
     */
    public static function updateFilterCreated(int $id): bool
    {
        $affected = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('id', $id)
            ->update(['filter_created_at' => Capsule::raw('NOW()')]);
        return $affected > 0;
    }

    /**
     * Salva o filter_name e failregex gerados pela IA on-demand em uma sugestão
     * que originalmente não tinha esses campos (sugestão antiga ou IA não gerou).
     */
    public static function updateSuggestionFilter(int $id, string $filterName, string $failregex): bool
    {
        $affected = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('id', $id)
            ->update([
                'filter_name' => substr(preg_replace('/[^a-z0-9-]/', '', strtolower($filterName)), 0, 64),
                'failregex'   => substr($failregex, 0, 1000),
            ]);
        return $affected > 0;
    }

    /**
     * Analisa ocorrências de um filter_name para o gate de auto-criação.
     *
     * Retorna:
     *   'occurrences'  — total de ocorrências (excluindo rejected)
     *   'distinct_ips' — IPs distintos que dispararam o padrão
     *   'best_failregex' — failregex mais frequente entre as ocorrências
     *   'window_days'  — janela de tempo usada (dias)
     *
     * Critérios (corrigidos):
     * - Exclui status 'rejected' (decisão explícita do admin não conta a favor)
     * - Janela de tempo configurável (default 30 dias)
     * - Conta IPs distintos (mesmo IP repetindo não prova generalização)
     * - Seleciona failregex mais frequente (não o último)
     * - Retorna todos os failregex distintos (top 5) para filtro multi-padrão
     * - Retorna source_log da ocorrência que forneceu o best_failregex
     */
    public static function analyzeFilterNameOccurrences(string $filterName, int $windowDays = 30): array
    {
        $since = date('Y-m-d H:i:s', time() - $windowDays * 86400);

        $rows = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('filter_name', $filterName)
            ->where('created_at', '>=', $since)
            ->where('status', '!=', 'rejected')
            ->orderBy('created_at', 'desc') // determinístico: mais recentes primeiro
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();

        $occurrences = count($rows);
        $ips = array_unique(array_column($rows, 'ip'));
        $distinctIps = count($ips);

        // Failregex por frequência (top 5, determinístico via ordenação prévia)
        $regexCounts = [];
        foreach ($rows as $r) {
            $fr = $r['failregex'] ?? '';
            if ($fr !== '') {
                $regexCounts[$fr] = ($regexCounts[$fr] ?? 0) + 1;
            }
        }
        arsort($regexCounts);
        $allFailregex = array_slice(array_keys($regexCounts), 0, 5);
        $bestFailregex = !empty($allFailregex) ? $allFailregex[0] : '';

        // source_log da ocorrência que forneceu o best_failregex
        $bestSourceLog = '';
        foreach ($rows as $r) {
            if (($r['failregex'] ?? '') === $bestFailregex && ($r['source_log'] ?? '') !== '') {
                $bestSourceLog = $r['source_log'];
                break;
            }
        }

        return [
            'occurrences'     => $occurrences,
            'distinct_ips'    => $distinctIps,
            'best_failregex'  => $bestFailregex,
            'all_failregex'   => $allFailregex,
            'best_source_log' => $bestSourceLog,
            'window_days'     => $windowDays,
        ];
    }

    /** Returns ban-time cross-reference for a list of IPs from the DB log. */
    public static function getBanInfoForIps(array $ips): array
    {
        if (empty($ips)) {
            return [];
        }
        $rows = Capsule::table('mod_amssoft_fail2ban_logs')
            ->whereIn('ip', $ips)
            ->whereIn('action', ['ban', 'manual_ban'])
            ->orderBy('timestamp', 'desc')
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();

        // Key by IP → most-recent record
        $map = [];
        foreach ($rows as $r) {
            if (!isset($map[$r['ip']])) {
                $map[$r['ip']] = $r;
            }
        }
        return $map;
    }

    // -----------------------------------------------------------------------
    // GeoIP cache
    // -----------------------------------------------------------------------

    /**
     * Retorna dados geo cacheados para um array de IPs.
     * Retorna array keyado por IP: ['1.2.3.4' => ['country'=>'BR', ...], ...]
     * Apenas registros dentro do TTL são retornados.
     *
     * [SEC-14] Usa whereIn com bind (Eloquent) e whereRaw com bind para DATE_SUB.
     */
    public static function getGeoCache(array $ips, int $ttlDays = 30): array
    {
        if (empty($ips)) {
            return [];
        }
        // Cálculo de data no MySQL para evitar discrepância de timezone PHP vs MySQL
        $rows = Capsule::table('mod_amssoft_fail2ban_geo_cache')
            ->whereIn('ip', $ips)
            ->whereRaw('updated_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$ttlDays])
            ->get()
            ->map(fn ($r) => (array)$r)
            ->all();

        $map = [];
        foreach ($rows as $r) {
            $map[$r['ip']] = $r;
        }
        return $map;
    }

    /**
     * Upsert em batch de dados geo.
     * Usa INSERT ... ON DUPLICATE KEY UPDATE em uma única query.
     */
    public static function setGeoCacheBatch(array $entries): void
    {
        if (empty($entries)) {
            return;
        }

        // Filtrar entries sem IP
        $valid = array_filter($entries, fn ($e) => !empty($e['ip']));
        if (empty($valid)) {
            return;
        }

        // Construir VALUES para multi-row INSERT
        $values   = [];
        $bindings = [];
        foreach ($valid as $entry) {
            $values[]   = '(?, ?, ?, ?, ?, ?)';
            $bindings[] = $entry['ip'];
            $bindings[] = $entry['country']      ?? null;
            $bindings[] = $entry['country_code'] ?? null;
            $bindings[] = $entry['region']       ?? null;
            $bindings[] = $entry['isp']          ?? null;
            $bindings[] = $entry['asn']          ?? null;
        }

        // [SEC-14] Nenhuma variável interpolada no SQL — todos os valores via bind params.
        $sql = 'INSERT INTO mod_amssoft_fail2ban_geo_cache '
             . '(ip, country, country_code, region, isp, asn) VALUES '
             . implode(', ', $values)
             . ' ON DUPLICATE KEY UPDATE '
             . 'country = VALUES(country), country_code = VALUES(country_code), '
             . 'region = VALUES(region), isp = VALUES(isp), asn = VALUES(asn), '
             . 'updated_at = NOW()';

        Capsule::connection()->statement($sql, $bindings);
    }

    /** Trunca a tabela de cache geo. */
    public static function clearGeoCache(): void
    {
        Capsule::table('mod_amssoft_fail2ban_geo_cache')->truncate();
    }

    /**
     * Remove registros expirados do cache geo.
     * [SEC-14] Usa DATE_SUB com bind param — sem interpolação de variável.
     */
    public static function cleanExpiredGeoCache(int $ttlDays = 30): int
    {
        // DELETE com bind param: DATE_SUB(NOW(), INTERVAL ? DAY)
        // Eloquent where() com operador '<' e valor numérico faz bind correto,
        // mas usamos raw() aqui para garantir que o cálculo de data seja feito no MySQL
        // (evita discrepância de timezone PHP vs MySQL).
        return Capsule::table('mod_amssoft_fail2ban_geo_cache')
            ->whereRaw('updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [$ttlDays])
            ->delete();
    }

    // -----------------------------------------------------------------------
    // GeoIP rate limit state
    // -----------------------------------------------------------------------

    /**
     * Retorna o estado do rate limit global do GeoIP.
     * ['requests_this_minute' => N, 'minute_window_start' => timestamp, 'cooldown_until' => timestamp]
     */
    public static function getGeoRateState(): array
    {
        $count    = (int) self::getConfig('geoip_requests_this_minute', '0');
        $window   = (int) self::getConfig('geoip_minute_window_start', '0');
        $cooldown = (int) self::getConfig('geoip_cooldown_until', '0');
        return [
            'requests_this_minute' => $count,
            'minute_window_start'  => $window,
            'cooldown_until'       => $cooldown,
        ];
    }

    /**
     * Salva o estado do rate limit global do GeoIP.
     *
     * ⚠️ Limitação conhecida: são 2-3 queries separadas (UPDATE por chave),
     * não uma transação atômica. Em cenário de admins simultâneos, um pode
     * sobrescrever a escrita do outro. Pior caso: contador ligeiramente
     * desatualizado — sem perda de dados, sem falha crítica. A margem de
     * segurança (40 em vez de 45) absorve esta imprecisão.
     *
     * @param int $count       Requests feitos no minuto atual
     * @param int $windowStart Timestamp do início da janela de 60s
     * @param int $cooldownUntil Timestamp até quando o cooldown 429 está ativo (0 = sem cooldown)
     */
    public static function setGeoRateState(int $count, int $windowStart, int $cooldownUntil = 0): void
    {
        self::setConfig('geoip_requests_this_minute', (string) $count);
        self::setConfig('geoip_minute_window_start', (string) $windowStart);
        if ($cooldownUntil > 0) {
            self::setConfig('geoip_cooldown_until', (string) $cooldownUntil);
        }
    }
}
