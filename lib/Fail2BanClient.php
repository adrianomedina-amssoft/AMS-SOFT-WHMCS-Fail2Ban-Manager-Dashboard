<?php
namespace AMS\Fail2Ban;

/**
 * Wrapper around `sudo fail2ban-client`.
 * All externally-derived values are whitelisted before being embedded in commands.
 */
class Fail2BanClient
{
    private string $sudo;
    private string $clientBin;

    public function __construct(string $sudo, string $clientBin)
    {
        $this->sudo      = $sudo;
        $this->clientBin = $clientBin;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /** Returns ['sshd', 'apache-auth', ...] */
    public function getJails(): array
    {
        $output = $this->run('status');
        // Output contains: `- Jail list:   sshd, apache-auth`
        if (preg_match('/Jail list:\s*(.+)/i', $output, $m)) {
            $jails = array_map('trim', explode(',', $m[1]));
            return array_values(array_filter($jails, fn ($j) => $j !== ''));
        }
        return [];
    }

    /**
     * Returns jail status array with keys:
     * currently_failed, total_failed, file_list, currently_banned, total_banned, banned_ip_list
     */
    public function getJailStatus(string $jail): array
    {
        $jail = $this->sanitizeJail($jail);
        if ($jail === '') {
            return $this->emptyStatus();
        }

        $output = $this->run('status ' . escapeshellarg($jail));

        $result = $this->emptyStatus();
        if (preg_match('/Currently failed:\s*(\d+)/i', $output, $m)) {
            $result['currently_failed'] = (int)$m[1];
        }
        if (preg_match('/Total failed:\s*(\d+)/i', $output, $m)) {
            $result['total_failed'] = (int)$m[1];
        }
        if (preg_match('/File list:\s*(.+)/i', $output, $m)) {
            $result['file_list'] = array_filter(array_map('trim', preg_split('/\s+/', $m[1])));
        }
        if (preg_match('/Currently banned:\s*(\d+)/i', $output, $m)) {
            $result['currently_banned'] = (int)$m[1];
        }
        if (preg_match('/Total banned:\s*(\d+)/i', $output, $m)) {
            $result['total_banned'] = (int)$m[1];
        }
        if (preg_match('/Banned IP list:\s*(.*)/i', $output, $m)) {
            $ips = array_filter(array_map('trim', preg_split('/\s+/', $m[1])));
            $result['banned_ip_list'] = array_values($ips);
        }

        return $result;
    }

    /**
     * Returns [['ip' => '1.2.3.4', 'jail' => 'sshd'], ...]
     * If $jail is null, iterates over all jails.
     */
    public function getBannedIPs(?string $jail = null): array
    {
        $jails = $jail !== null ? [$jail] : $this->getJails();
        $result = [];

        foreach ($jails as $j) {
            $status = $this->getJailStatus($j);
            foreach ($status['banned_ip_list'] as $ip) {
                if ($ip !== '') {
                    $result[] = ['ip' => $ip, 'jail' => $j];
                }
            }
        }

        return $result;
    }

    public function unbanIP(string $jail, string $ip): bool
    {
        $jail = $this->sanitizeJail($jail);
        $ip   = $this->sanitizeIp($ip);
        if ($jail === '' || $ip === '') {
            return false;
        }
        $this->run('set ' . escapeshellarg($jail) . ' unbanip ' . escapeshellarg($ip), $code);
        return $code === 0;
    }

    public function banIP(string $jail, string $ip): bool
    {
        $jail = $this->sanitizeJail($jail);
        $ip   = $this->sanitizeIp($ip);
        if ($jail === '' || $ip === '') {
            return false;
        }
        $this->run('set ' . escapeshellarg($jail) . ' banip ' . escapeshellarg($ip), $code);
        return $code === 0;
    }

    /** Reloads a specific jail, or the entire fail2ban service if $jail is null. */
    public function reload(?string $jail = null): bool
    {
        if ($jail !== null) {
            $jail = $this->sanitizeJail($jail);
            if ($jail === '') {
                return false;
            }
            $this->run('reload ' . escapeshellarg($jail), $code);
        } else {
            $this->run('reload', $code);
        }
        return $code === 0;
    }

    /** Returns true when fail2ban responds to ping. */
    public function ping(): bool
    {
        $this->run('ping', $code);
        return $code === 0;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Builds and executes: sudo fail2ban-client <cmd>
     * $cmd must be constructed from sanitized/escaped values within this class.
     */
    private function run(string $cmd, &$code = 0): string
    {
        $fullCmd = escapeshellarg($this->sudo)
            . ' '
            . escapeshellarg($this->clientBin)
            . ' '
            . $cmd
            . ' 2>&1';

        $outputArr = [];
        exec($fullCmd, $outputArr, $code);
        return implode("\n", $outputArr);
    }

    private function sanitizeJail(string $jail): string
    {
        // [SEC-4] First character must be alphanumeric; prevents names like "-h" being
        // passed as CLI flags to fail2ban-client.
        return preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/', $jail) ? $jail : '';
    }

    private function sanitizeIp(string $ip): string
    {
        $ip = trim($ip);
        return (filter_var($ip, FILTER_VALIDATE_IP) !== false) ? $ip : '';
    }

    private function emptyStatus(): array
    {
        return [
            'currently_failed' => 0,
            'total_failed'     => 0,
            'file_list'        => [],
            'currently_banned' => 0,
            'total_banned'     => 0,
            'banned_ip_list'   => [],
        ];
    }
}
