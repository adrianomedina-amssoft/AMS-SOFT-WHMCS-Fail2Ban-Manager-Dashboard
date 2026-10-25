<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Read-only view model. Never an input to blocking or paid admission. */
final class DashboardOverview
{
    public static function jailNames(string $output): array
    {
        if (!preg_match('/Number of jail:[ \t]*(\d+)/', $output, $count)
            || !preg_match('/Jail list:[ \t]*([^\r\n]*)/', $output, $list)) throw new \RuntimeException('Incomplete native list');
        $names = trim($list[1]) === '' ? [] : array_map('trim', explode(',', $list[1]));
        if (count($names) !== (int)$count[1] || count(array_unique($names)) !== count($names)) throw new \RuntimeException('Inconsistent native list');
        foreach ($names as $name) if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D', $name)) throw new \RuntimeException('Invalid jail name');
        sort($names);
        return $names;
    }

    public static function jailStatus(string $output): array
    {
        $row = [];
        foreach (['currently_failed'=>'Currently failed', 'total_failed'=>'Total failed',
            'currently_banned'=>'Currently banned', 'total_banned'=>'Total banned'] as $key=>$label) {
            if (!preg_match('/'.preg_quote($label, '/').':[ \t]*(\d+)(?:\r?\n|$)/', $output, $match)
                || strlen($match[1]) > 18) throw new \RuntimeException('Incomplete native counters');
            $row[$key] = (int)$match[1];
        }
        if (!preg_match('/Banned IP list:[ \t]*([^\r\n]*)/', $output, $match)) throw new \RuntimeException('Missing native peers');
        $ips = trim($match[1]) === '' ? [] : preg_split('/\s+/', trim($match[1]));
        $canonical = [];
        foreach ($ips as $ip) {
            $peer = Safety::canonicalIp($ip);
            if ($peer === null) throw new \RuntimeException('Invalid native peer');
            $canonical[$peer] = true;
        }
        if (count($ips) !== $row['currently_banned'] || count($canonical) !== count($ips)) throw new \RuntimeException('Inconsistent native peers');
        $row['banned_ip_list'] = array_keys($canonical);
        return $row;
    }

    public static function native(array $vars, ?callable $read = null): array
    {
        // Validated helper27 presentation read; effective firewall coverage is
        // still checked independently by decisions(), never inferred from bans.
        if ($read === null) {
            $snapshot = IpBanSnapshot::read();
            unset($snapshot['identities']);
            return $snapshot;
        }
        // Explicit reader injection is retained for compatibility/parser tests.
        // Helper failure must never fall back to per-jail CLI processes.
        $start = hrtime(true);
        $out = ['online'=>null, 'complete'=>false, 'jails'=>null, 'unique_ips'=>null,
            'tickets'=>null, 'statuses'=>[], 'at'=>time(), 'error'=>null];
        $query = static function(array $args) use ($read, $start): string {
            $remaining = 15 - (hrtime(true)-$start)/1e9;
            if ($remaining <= 0) throw new \RuntimeException('Native read deadline');
            return $read($args, min(2.0, $remaining));
        };
        try {
            $names = self::jailNames($query(['status']));
            $out['online'] = true; $out['jails'] = count($names);
            $ips = []; $tickets = 0; $failed = false;
            foreach ($names as $name) {
                try {
                    $row = self::jailStatus($query(['status', $name]));
                    $out['statuses'][$name] = $row;
                    foreach ($row['banned_ip_list'] as $ip) $ips[$ip] = true;
                    $tickets += $row['currently_banned'];
                } catch (\Throwable $e) { $out['statuses'][$name] = null; $failed = true; }
            }
            if (self::jailNames($query(['status'])) !== $names) {
                $out['jails'] = null;
                throw new \RuntimeException('Jail list changed');
            }
            if ($failed) throw new \RuntimeException('Partial native read');
            $out['unique_ips'] = count($ips); $out['tickets'] = $tickets; $out['complete'] = true;
        } catch (\Throwable $e) {
            $out['error'] = 'Consulta do Fail2Ban incompleta ou indisponível. Totais não confirmados; consulte Proteção e manutenção.';
        }
        $out['seconds'] = round((hrtime(true)-$start)/1e9, 3);
        return $out;
    }

    public static function history(int $now): array
    {
        $q = Capsule::table('mod_amssoft_fail2ban_logs')->whereIn('action', ['ban','manual_ban'])
            ->where('timestamp', '<=', date('Y-m-d H:i:s', $now));
        $since = date('Y-m-d', strtotime('-6 days', $now)).' 00:00:00';
        $series = (clone $q)->where('timestamp', '>=', $since)->selectRaw('DATE(timestamp) AS date, COUNT(*) AS count')
            ->groupByRaw('DATE(timestamp)')->orderByRaw('DATE(timestamp)')->get()->map(fn($r)=>(array)$r)->all();
        $map = array_column($series, 'count', 'date'); $days = [];
        for ($i=6; $i>=0; $i--) {
            $date = date('Y-m-d', strtotime('-'.$i.' days', $now));
            $days[] = ['date'=>$date, 'count'=>(int)($map[$date]??0)];
        }
        $last = (clone $q)->orderByDesc('timestamp')->orderByDesc('id')->first(['ip','jail','timestamp']);
        $top = (clone $q)->select('ip')->selectRaw('COUNT(*) AS count')->groupBy('ip')
            ->orderByDesc('count')->orderBy('ip')->limit(10)->get()->map(fn($r)=>(array)$r)->all();
        $created = Capsule::table('mod_amssoft_fail2ban_logs')->where('action','jail_created')
            ->where('timestamp','>=',date('Y-m-d', $now).' 00:00:00')->where('timestamp','<=',date('Y-m-d H:i:s',$now));
        return ['count_24h'=>(int)(clone $q)->where('timestamp','>=',date('Y-m-d H:i:s',$now-86400))->count(),
            'last'=>$last?(array)$last:null, 'days'=>$days, 'top'=>$top,
            'created_today'=>(int)(clone $created)->count(),
            'created_recent'=>(clone $created)->orderByDesc('timestamp')->orderByDesc('id')->limit(5)->get(['jail','timestamp'])->map(fn($r)=>(array)$r)->all()];
    }

    public static function decisions(): array
    {
        if (!DecisionProtection::enabled()) throw new \RuntimeException('Projection unavailable');
        $total = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('status','pending')->where('classification','ban')->count();
        if ($total > 5000) throw new \RuntimeException('Presentation limit');
        if ($total === 0) return ['counts'=>array_fill_keys(DecisionProtection::VIEWS,0), 'at'=>time()];
        $snapshot = Privileged::run(['--read-budget','15','dashboard-protection-snapshot']);
        $snapshot['ttl'] = Policy::number('ai_blocked_recheck_seconds');
        if (($snapshot['success']??false)!==true || ($snapshot['stable']??false)!==true || !empty($snapshot['errors'])
            || !is_int($snapshot['observed_at']??null) || $snapshot['observed_at']>time()
            || $snapshot['observed_at']+$snapshot['ttl']<=time()) throw new \RuntimeException('Coverage unavailable');
        $projection = DecisionProtection::refresh($snapshot, false);
        if ($snapshot['observed_at']+$snapshot['ttl']<=time()) throw new \RuntimeException('Coverage expired');
        return ['counts'=>array_map('count',$projection['groups']), 'at'=>$projection['observed_at']];
    }

    public static function read(array $vars): array
    {
        return Database::withPresentationConfigCache(static function() use ($vars): array {
            $out = ['at'=>time(), 'native'=>self::native($vars), 'history'=>null, 'ai'=>null,
                'decisions'=>null, 'last_analysis'=>null, 'last_analysis_known'=>false, 'geo'=>[], 'errors'=>[]];
            try { $out['history'] = self::history($out['at']); }
            catch (\Throwable $e) { $out['errors'][] = 'Histórico do módulo indisponível; os valores não foram medidos.'; }
            try {
                $values = Policy::values();
                $health = ['collector'=>Database::getConfig('ai_collector_heartbeat'),
                    'collector_error'=>Database::getConfig('ai_collector_error',''),
                    'cycle'=>Database::getConfig('ai_cycle_heartbeat'), 'error'=>Database::getConfig('ai_last_error',''),
                    'telemetry'=>['state'=>json_decode(Database::getConfig('ai_cycle_state','null'),true)]];
                $provider = Database::getConfig('ai_active_provider','anthropic');
                $out['ai'] = ['enabled'=>$values['ai_auto_enabled']==='1', 'mode'=>$values['ai_mode'], 'provider'=>$provider,
                    'saved_ping'=>Database::getConfig('ai_provider_'.$provider.'_last_ping','0'),
                    'states'=>ProtectionView::states($values,$health,(int)Database::getConfig('ai_last_run','0'),time()),
                    'collector'=>$health['collector'], 'cycle'=>$health['cycle']];
            } catch (\Throwable $e) { $out['errors'][] = 'Estado da automação indisponível; configuração não confirmada.'; }
            try { $out['decisions'] = self::decisions(); }
            catch (\Throwable $e) { $out['errors'][] = 'Decisões acionáveis não medidas. A consulta não altera a fila; verifique a tela IA.'; }
            try {
                $row = Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->orderByDesc('created_at')->orderByDesc('id')
                    ->first(['ip','threat','classification','status','severity','confidence','created_at']);
                $out['last_analysis'] = $row?(array)$row:null; $out['last_analysis_known'] = true;
            } catch (\Throwable $e) { $out['errors'][] = 'Última análise indisponível.'; }
            if (!empty($out['history']['last']['ip'])) {
                try { $out['geo'] = Database::getGeoCache([$out['history']['last']['ip']]); }
                catch (\Throwable $e) { /* Optional cache-only enrichment. */ }
            }
            $out['finished_at'] = time();
            return $out;
        });
    }
}
