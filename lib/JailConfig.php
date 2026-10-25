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
    private string $expectedHash = '';
    private ?string $uiExpectedHash = null;
    private bool $preserveActions = false;

    /** UI optimistic guard. The privileged installer also checks the file hash. */
    public function guardUiWrite(string $hash): void
    {
        $this->uiExpectedHash = $hash;
        $this->preserveActions = true;
    }

    public function localHash(): string
    {
        $hash = @hash_file('sha256', $this->jailLocalPath);
        if (!is_string($hash)) throw new \RuntimeException('Configuração local indisponível.');
        return $hash;
    }

    public function appliesOnWrite(): bool
    {
        return $this->jailLocalPath === '/etc/fail2ban/jail.local';
    }

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

    public function readEffective(): array
    {
        $result=Privileged::run(['effective-config']);
        if(empty($result['success'])) throw new \RuntimeException('Leitura nativa de configuração indisponível.');
        return $result['jails'];
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
        if ($path === '/etc/fail2ban/jail.local') {
            return !empty(Privileged::run(['health'])['success']) ? null
                : 'Helper privilegiado indisponível. Instale setup/amsfb-admin como root e atualize o sudoers.';
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
        return $this->change($jail, $params, 'save');
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
        return $this->change($jail, $params, 'add');
    }

    /**
     * Removes a jail section from jail.local entirely.
     * Returns false if the jail does not exist.
     */
    public function removeJail(string $jail): bool
    {
        return $this->change($jail, [], 'remove');
    }

    private function change(string $jail, array $params, string $operation): bool
    {
        if (Helper::sanitizeJail($jail) === '' || in_array($jail, ['DEFAULT', 'INCLUDES'], true)) return false;
        $lock = LogLock::acquire('jail-config:' . $this->jailLocalPath);
        if ($lock['fp'] === null) return false;
        try {
            $original = is_file($this->jailLocalPath) ? file_get_contents($this->jailLocalPath) : '';
            if ($original === false) return false;
            $this->expectedHash = hash('sha256', $original);
            if ($this->uiExpectedHash !== null && !hash_equals($this->uiExpectedHash, $this->expectedHash)) return false;
            $data = $this->parseIni($original);
            if ($operation === 'add' && isset($data[$jail])) return false;
            if ($operation === 'remove') {
                if (!isset($data[$jail])) return false;
                unset($data[$jail]);
            } else {
                $isNew = !isset($data[$jail]);
                $data[$jail] = $data[$jail] ?? [];
                foreach ($params as $key => $value) {
                    if (in_array($key, ['enabled','maxretry','findtime','bantime','logpath','filter','action','ignoreip'], true)) {
                        $data[$jail][$key] = preg_replace('/[\x00-\x1F\x7F]/', '', (string)$value);
                    }
                }
                $nativeExisting=false;
                if($isNew&&$this->jailLocalPath==='/etc/fail2ban/jail.local') {
                    try {$nativeExisting=isset($this->readEffective()[$jail]);}catch(CycleBudgetExceeded $e){throw $e;}catch(\Throwable $e){return false;}
                }
                if (($isNew&&!$nativeExisting) || (!$this->preserveActions && (str_starts_with($jail, 'amsfb-') || strlen('f2b-' . $jail) > 28))) {
                    $data[$jail]['action'] = 'iptables-multiport[name=' . Safety::actionName($jail) . ',port="0:65535"]';
                }
            }
            return $this->writeFile($data);
        } finally {
            LogLock::release($lock['fp']);
        }
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

    /** Returns the output captured from the last reload command (useful for diagnostics on failure). */
    public function getLastReloadOutput(): string
    {
        return $this->client ? $this->client->getLastOutput() : '';
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private function parseIni(string $content): array
    {
        $result  = [];
        $section = null;
        $lastKey = null;
        $lastIndent = 0;

        foreach (explode("\n", $content) as $rawLine) {
            $line    = rtrim($rawLine);
            $trimmed = ltrim($line);

            if ($trimmed === '' || $trimmed[0] === '#' || $trimmed[0] === ';') {
                continue;
            }

            // Section header
            if (preg_match('/^\[([^\]]+)\]/', $trimmed, $m)) {
                $lastKey = null;
                $section = trim($m[1]);
                if (!isset($result[$section])) {
                    $result[$section] = [];
                }
                continue;
            }

            $indent = strlen($line) - strlen(ltrim($line));
            if ($section !== null && $lastKey !== null && $indent > $lastIndent) {
                $result[$section][$lastKey] .= "\n" . $trimmed;
                continue;
            }
            // Preserve literal semicolons and interpolation in existing values.
            if ($section !== null && strpos($trimmed, '=') !== false) {
                [$k, $v]            = explode('=', $trimmed, 2);
                $k                  = trim($k);
                $v                  = trim($v);
                $result[$section][$k] = $v;
                $lastKey = $k;
                $lastIndent = $indent;
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
                $value = str_replace("\n", "\n            ", $value);
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
        if ($this->jailLocalPath === '/etc/fail2ban/jail.local') {
            $result = Privileged::run(['install-jail', $tmp, $this->expectedHash]);
            $ok = !empty($result['success']);
        } else {
            $local = tempnam(dirname($this->jailLocalPath), '.amsfb-');
            $ok = $local !== false && file_put_contents($local, $header . $body, LOCK_EX) !== false;
            if ($ok) {
                if (is_file($this->jailLocalPath) && $this->backup() === '') $ok = false;
                if ($ok) {
                    @chmod($local, is_file($this->jailLocalPath) ? (fileperms($this->jailLocalPath) & 0777) : 0640);
                    $ok = rename($local, $this->jailLocalPath);
                }
            }
            if ($local !== false && is_file($local)) @unlink($local);
        }
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
        return copy($this->jailLocalPath, $dst) ? $dst : '';
    }
}
