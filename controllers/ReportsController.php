<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;

class ReportsController
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
        $do = $_GET['do'] ?? '';

        if ($do === 'export_csv') {
            $this->exportCsv();
            return ''; // unreachable
        }

        return $this->showReports();
    }

    // -----------------------------------------------------------------------
    // CSV export — outputs directly and exits
    // -----------------------------------------------------------------------

    private function exportCsv(): void
    {
        $filters = $this->collectFilters();
        $rows    = Database::searchHistory($filters)->all();

        // Clear any buffered WHMCS output
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="fail2ban_report_' . date('Ymd_His') . '.csv"');
        header('Pragma: no-cache');
        header('Expires: 0');

        $fh = fopen('php://output', 'w');
        if ($fh === false) {
            exit;
        }

        // UTF-8 BOM (for Excel compatibility)
        fputs($fh, "\xEF\xBB\xBF");

        // Header row
        fputcsv($fh, ['timestamp', 'ip', 'jail', 'action', 'reason', 'admin_id']);

        foreach ($rows as $row) {
            fputcsv($fh, [
                $row['timestamp'] ?? '',
                $row['ip']        ?? '',
                $row['jail']      ?? '',
                $row['action']    ?? '',
                $row['reason']    ?? '',
                $row['admin_id']  ?? '',
            ]);
        }

        fclose($fh);
        exit;
    }

    // -----------------------------------------------------------------------
    // Show reports page
    // -----------------------------------------------------------------------

    private function showReports(): string
    {
        $filters   = $this->collectFilters();
        $page      = max(1, (int)($_GET['page'] ?? 1));
        $result    = [];
        $jailsList = [];

        try {
            $result    = Database::searchHistoryPaged($filters, $page, 50);
            $jailsList = Database::getKnownJails();
        } catch (\Throwable $e) {
            $result = ['data' => [], 'total' => 0, 'pages' => 0, 'page' => 1];
        }

        return $this->router->render('reports', [
            'rows'      => $result['data'],
            'total'     => $result['total'],
            'pages'     => $result['pages'],
            'page'      => $result['page'],
            'filters'   => $filters,
            'jails'     => $jailsList,
            'actions'   => ['ban', 'unban', 'manual_ban', 'manual_unban'],
        ]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function collectFilters(): array
    {
        return [
            'date_from' => $this->sanitizeDate($_GET['date_from'] ?? ''),
            'date_to'   => $this->sanitizeDate($_GET['date_to']   ?? ''),
            'ip'        => Helper::sanitizeIp($_GET['ip'] ?? '') ?? '',
            'jail'      => Helper::sanitizeJail($_GET['jail'] ?? ''),
            'action'    => $this->sanitizeAction($_GET['action_filter'] ?? ''),
        ];
    }

    private function sanitizeDate(string $d): string
    {
        return preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) ? $d : '';
    }

    private function sanitizeAction(string $a): string
    {
        $valid = ['ban', 'unban', 'manual_ban', 'manual_unban'];
        return in_array($a, $valid, true) ? $a : '';
    }
}
