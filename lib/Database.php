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
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->where('timestamp', '>=', Capsule::raw("NOW() - INTERVAL {$hours} HOUR"))
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
        return Capsule::table('mod_amssoft_fail2ban_logs')
            ->select(
                Capsule::raw('DATE(timestamp) AS `date`'),
                Capsule::raw('COUNT(*) AS `count`')
            )
            ->whereIn('action', ['ban', 'manual_ban'])
            ->where('timestamp', '>=', Capsule::raw("NOW() - INTERVAL {$days} DAY"))
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
