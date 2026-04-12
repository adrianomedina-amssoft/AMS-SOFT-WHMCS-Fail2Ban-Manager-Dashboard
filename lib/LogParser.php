<?php
namespace AMS\Fail2Ban;

class LogParser
{
    /**
     * Validate that a log file path exists and is readable.
     * Returns ['exists' => bool, 'readable' => bool, 'size' => int (bytes)]
     */
    public function validateLogPath(string $path): array
    {
        // Reject path-traversal attempts
        if (strpos($path, '..') !== false || !str_starts_with($path, '/')) {
            return ['exists' => false, 'readable' => false, 'size' => 0];
        }

        $exists   = file_exists($path);
        $readable = $exists && is_readable($path);
        $size     = $readable ? (int)filesize($path) : 0;

        return [
            'exists'   => $exists,
            'readable' => $readable,
            'size'     => $size,
        ];
    }

    /**
     * Parse a fail2ban log file for ban/unban events since $sinceTs (unix timestamp).
     * Returns [['ts' => int, 'action' => 'ban'|'unban', 'jail' => string, 'ip' => string], ...]
     *
     * Supported fail2ban log format:
     *   2026-04-11 10:00:01,234 fail2ban.actions [123]: WARNING [sshd] Ban 1.2.3.4
     *   2026-04-11 10:00:01,234 fail2ban.actions [123]: NOTICE  [sshd] Unban 1.2.3.4
     */
    public function parseLogFile(string $path, int $sinceTs = 0): array
    {
        $info = $this->validateLogPath($path);
        if (!$info['readable']) {
            return [];
        }

        $fh = @fopen($path, 'r');
        if ($fh === false) {
            return [];
        }

        $pattern = '/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban\.\S+\s+\[\d+\]:\s+\S+\s+\[([^\]]+)\]\s+(Ban|Unban)\s+(\S+)/i';
        $results = [];

        while (($line = fgets($fh)) !== false) {
            if (!preg_match($pattern, $line, $m)) {
                continue;
            }
            $ts = strtotime($m[1]);
            if ($ts === false || ($sinceTs > 0 && $ts < $sinceTs)) {
                continue;
            }
            $results[] = [
                'ts'     => $ts,
                'action' => (strtolower($m[3]) === 'ban') ? 'ban' : 'unban',
                'jail'   => $m[2],
                'ip'     => $m[4],
            ];
        }

        fclose($fh);
        return $results;
    }

    /**
     * Count "Found" lines for $jail in the default fail2ban log within the last $minutes.
     */
    public function getRecentFailures(string $jail, int $minutes = 60): int
    {
        $path = '/var/log/fail2ban.log';
        if (!is_readable($path)) {
            return 0;
        }

        $sinceTs = time() - ($minutes * 60);
        $count   = 0;
        $fh      = @fopen($path, 'r');
        if ($fh === false) {
            return 0;
        }

        // Sanitize jail for use in regex
        $jailEscaped = preg_quote($jail, '/');
        $pattern     = '/fail2ban\.\S+.*\[' . $jailEscaped . '\]\s+Found/i';

        while (($line = fgets($fh)) !== false) {
            if (!preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $line, $m)) {
                continue;
            }
            $ts = strtotime($m[1]);
            if ($ts !== false && $ts >= $sinceTs && preg_match($pattern, $line)) {
                $count++;
            }
        }

        fclose($fh);
        return $count;
    }
}
