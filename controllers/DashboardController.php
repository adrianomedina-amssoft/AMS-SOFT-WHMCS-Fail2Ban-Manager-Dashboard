<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Router;

class DashboardController
{
    private array  $vars;
    private Router $router;

    public function __construct(array $vars, Router $router)
    {
        $this->vars   = $vars;
        $this->router = $router;
    }

    public function handle(string $action): string
    {
        $client         = $this->router->makeClient();
        $fail2banOnline = false;
        $jails          = [];
        $jailStatuses   = [];
        $totalBannedNow = 0;
        $error          = null;

        try {
            $fail2banOnline = $client->ping();
            if ($fail2banOnline) {
                $jails = $client->getJails();
                foreach ($jails as $jail) {
                    $status = $client->getJailStatus($jail);
                    $jailStatuses[$jail] = $status;
                    $totalBannedNow += $status['currently_banned'];
                }
            }
        } catch (\Throwable $e) {
            $error = $e->getMessage();
        }

        $recentBans = [];
        $topIPs     = [];
        $banSeries  = [];

        // Dados da IA para o card do dashboard
        $aiPendingCount  = 0;
        $aiLastSuggestion = null;
        $aiMode          = 'suggestion';
        $aiApiOk         = '0';

        try {
            $recentBans       = Database::getRecentBans(24);
            $topIPs           = Database::getTopBannedIps(10);
            $banSeries        = Database::getBansSeries(7);
            $aiPendingCount   = Database::countPendingSuggestions();
            $aiLastSuggestion = Database::getLastSuggestion();
            $aiMode           = Database::getConfig('ai_mode', 'suggestion');
            $aiApiOk          = Database::getConfig('ai_last_ping_ok', '0');
        } catch (\Throwable $e) {
            // Tables may not exist yet (before activate())
        }

        $lastBan = !empty($recentBans) ? $recentBans[0] : null;

        // Build a full 7-day series filling in zeroes for missing days
        $seriesMap = [];
        foreach ($banSeries as $row) {
            $seriesMap[$row['date']] = (int)$row['count'];
        }

        $seriesLabels = [];
        $seriesCounts = [];
        $now = time();
        for ($i = 6; $i >= 0; $i--) {
            $d              = date('Y-m-d', $now - $i * 86400);
            $seriesLabels[] = $d;
            $seriesCounts[] = $seriesMap[$d] ?? 0;
        }

        $topIpLabels = [];
        $topIpCounts = [];
        foreach ($topIPs as $row) {
            $topIpLabels[] = $row['ip'];
            $topIpCounts[] = (int)$row['count'];
        }

        // [SEC-6] Use JSON_HEX_TAG so that < and > in data values (e.g., IPs from a
        // compromised DB row) cannot emit literal HTML tags inside the <script> block.
        $jsonFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;

        return $this->router->render('dashboard', [
            'fail2ban_online'   => $fail2banOnline,
            'error'             => $error,
            'total_banned_now'  => $totalBannedNow,
            'bans_24h'          => count($recentBans),
            'active_jails'      => count($jails),
            'last_ban'          => $lastBan,
            'jail_statuses'     => $jailStatuses,
            'series_labels'     => json_encode($seriesLabels, $jsonFlags),
            'series_counts'     => json_encode($seriesCounts, $jsonFlags),
            'top_ip_labels'     => json_encode($topIpLabels,  $jsonFlags),
            'top_ip_counts'     => json_encode($topIpCounts,  $jsonFlags),
            'ai_pending_count'  => $aiPendingCount,
            'ai_last_suggestion'=> $aiLastSuggestion,
            'ai_mode'           => $aiMode,
            'ai_api_ok'         => $aiApiOk,
        ]);
    }
}
