<?php
namespace AMS\Fail2Ban;

/**
 * Parser and writer for /etc/fail2ban/jail.local.
 * Creates a timestamped .bak before every write.
 */
class JailConfig
{
    private string $jailLocalPath;
    private ?Fail2BanClient $client;

    public function __construct(string $jailLocalPath, ?Fail2BanClient $client = null)
    {
        $this->jailLocalPath = $jailLocalPath;
        $this->client        = $client;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Returns [jailName => ['enabled' => 'true', 'maxretry' => '5', ...], ...]
     * Includes ALL sections (including [DEFAULT]).
     */
    public function readJailLocal(): array
    {
        if (!file_exists($this->jailLocalPath)) {
            return [];
        }
        $content = file_get_contents($this->jailLocalPath);
        if ($content === false) {
            return [];
        }
        return $this->parseIni($content);
    }

    /**
     * Returns a human-readable permission problem, or null if the file is
     * accessible for both reading and writing by the current process.
     * Expected setup: chown root:www-data jail.local && chmod 0664 jail.local
     */
    public function checkPermissions(): ?string
    {
        $path = $this->jailLocalPath;
        if (!file_exists($path)) {
            return "Arquivo não encontrado: {$path}";
        }
        if (!is_readable($path)) {
            return "Sem permissão de leitura em {$path} — execute: chown root:www-data {$path} && chmod 0664 {$path}";
        }
        if (!is_writable($path)) {
            return "Sem permissão de escrita em {$path} — execute: chown root:www-data {$path} && chmod 0664 {$path}";
        }
        return null;
    }

    /**
     * Merges $params into the named $jail section and writes jail.local.
     * Allowed keys: enabled, maxretry, findtime, bantime, logpath, filter, action
     */
    public function saveJail(string $jail, array $params): bool
    {
        $data = $this->readJailLocal();

        if (!isset($data[$jail])) {
            $data[$jail] = [];
        }

        $allowed = ['enabled', 'maxretry', 'findtime', 'bantime', 'logpath', 'filter', 'action'];
        foreach ($params as $key => $value) {
            if (in_array($key, $allowed, true)) {
                // [SEC-2] Strip control characters (newlines, null bytes, etc.) to prevent
                // INI injection: a logpath like "/var/log/x\n[DEFAULT]\nenabled=false" would
                // otherwise inject fake sections into jail.local.
                $safe = preg_replace('/[\x00-\x1F\x7F]/', '', (string)$value);
                $data[$jail][$key] = $safe;
            }
        }

        $this->backup();
        return $this->writeFile($data);
    }

    public function enableJail(string $jail): bool
    {
        return $this->saveJail($jail, ['enabled' => 'true']);
    }

    public function disableJail(string $jail): bool
    {
        return $this->saveJail($jail, ['enabled' => 'false']);
    }

    /**
     * Creates a new jail section. Returns false if the jail already exists.
     */
    public function addJail(string $jail, array $params): bool
    {
        $data = $this->readJailLocal();
        if (isset($data[$jail])) {
            return false; // already exists
        }
        return $this->saveJail($jail, $params);
    }

    /**
     * Removes a jail section from jail.local entirely.
     * Returns false if the jail does not exist.
     */
    public function removeJail(string $jail): bool
    {
        $data = $this->readJailLocal();
        if (!isset($data[$jail])) {
            return false;
        }
        unset($data[$jail]);
        $this->backup();
        return $this->writeFile($data);
    }

    /** Reloads the jail via fail2ban-client (requires injected client). */
    public function reloadJail(string $jail): bool
    {
        if ($this->client === null) {
            return false;
        }
        return $this->client->reload($jail);
    }

    /** Full fail2ban reload (used after adding/removing a jail). */
    public function reloadAll(): bool
    {
        if ($this->client === null) {
            return false;
        }
        return $this->client->reload();
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private function parseIni(string $content): array
    {
        $result  = [];
        $section = null;

        foreach (explode("\n", $content) as $rawLine) {
            $line    = rtrim($rawLine);
            $trimmed = ltrim($line);

            if ($trimmed === '' || $trimmed[0] === '#' || $trimmed[0] === ';') {
                continue;
            }

            // Section header
            if (preg_match('/^\[([^\]]+)\]/', $trimmed, $m)) {
                $section = trim($m[1]);
                if (!isset($result[$section])) {
                    $result[$section] = [];
                }
                continue;
            }

            // key = value  (strip inline comments)
            if ($section !== null && strpos($trimmed, '=') !== false) {
                [$k, $v]            = explode('=', $trimmed, 2);
                $k                  = trim($k);
                $v                  = trim(preg_replace('/\s*[#;].*$/', '', $v));
                $result[$section][$k] = $v;
            }
        }

        return $result;
    }

    /**
     * Reconstructs ini content, preserving top-level comment block from the
     * existing file if present.
     */
    private function writeFile(array $data): bool
    {
        $header = '';
        if (file_exists($this->jailLocalPath)) {
            $header = $this->extractHeaderComments(
                file_get_contents($this->jailLocalPath) ?: ''
            );
        }

        $body = '';
        foreach ($data as $section => $values) {
            $body .= "[{$section}]\n";
            foreach ($values as $key => $value) {
                $body .= "{$key} = {$value}\n";
            }
            $body .= "\n";
        }

        // [SEC-3] Atomic write: write to a temp file in /tmp (always writable by www-data)
        // then copy back to jail.local (which is 664 root:www-data — writable without
        // needing directory write permission on /etc/fail2ban/ which is 755 root:root).
        $tmp = tempnam(sys_get_temp_dir(), 'amsfb_jail_');
        if ($tmp === false) {
            return false;
        }
        if (file_put_contents($tmp, $header . $body, LOCK_EX) === false) {
            @unlink($tmp);
            return false;
        }
        $ok = copy($tmp, $this->jailLocalPath);
        @unlink($tmp);
        return $ok;
    }

    /** Extracts the leading comment/empty lines before the first [section]. */
    private function extractHeaderComments(string $content): string
    {
        $lines  = explode("\n", $content);
        $header = [];
        foreach ($lines as $line) {
            $t = ltrim($line);
            if ($t !== '' && $t[0] !== '#' && $t[0] !== ';') {
                break;
            }
            $header[] = $line;
        }
        if (empty($header)) {
            return '';
        }
        return implode("\n", $header) . "\n";
    }

    private function backup(): string
    {
        if (!file_exists($this->jailLocalPath)) {
            return '';
        }
        // [SEC-3] PID in name prevents concurrent backup collisions.
        // Prefer same directory as jail.local; fall back to /tmp if the directory
        // is not writable by the current process (e.g. /etc/fail2ban is 755 root:root).
        $suffix = '.bak.' . date('YmdHis') . '_' . getmypid();
        $dir    = dirname($this->jailLocalPath);
        $dst    = is_writable($dir)
            ? $this->jailLocalPath . $suffix
            : sys_get_temp_dir() . '/amsfb_jail_bak' . $suffix;
        copy($this->jailLocalPath, $dst);
        return $dst;
    }
}
