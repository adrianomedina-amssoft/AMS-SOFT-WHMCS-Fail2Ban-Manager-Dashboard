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

    // -----------------------------------------------------------------------
    // Sugestões da IA
    // -----------------------------------------------------------------------

    /** Salva uma nova sugestão da IA e retorna o ID inserido. */
    public static function saveSuggestion(array $data): int
    {
        // Upsert: se já existe sugestão pending para o mesmo IP+jail, não duplica
        $existing = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')
            ->where('ip',     $data['ip']   ?? '')
            ->where('jail',   $data['jail'] ?? '')
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
}
