<?php
namespace AMS\Fail2Ban;

/**
 * LogViewer — leitura e análise de arquivos de log configurados no módulo.
 */
class LogViewer
{
    // Padrões que indicam linhas suspeitas (para highlight)
    private const SUSPICIOUS_PATTERNS = [
        'wp-login', 'xmlrpc', '.env', 'phpMyAdmin', 'phpmyadmin',
        'wp-admin', '.git', 'eval(', 'base64_decode', '../',
        'select%20', 'union%20', 'passwd', 'shadow', 'etc/passwd',
        '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell',
    ];

    // Padrões que indicam linhas de erro
    private const ERROR_PATTERNS = [
        'error', 'Error', 'ERROR', 'fail', 'Fail', 'FAIL',
        'denied', 'Denied', 'refused', 'Refused',
        'Ban ', 'WARNING', 'CRITICAL',
    ];

    /**
     * Retorna todos os logs disponíveis para visualização.
     *
     * Fontes (sem duplicar paths):
     *  1. DB — chaves `logpath.*` gravadas pela tela Log Paths
     *  2. $extra — ['path' => 'label'] vindo do jail.local (passado pelo controller)
     *  3. /var/log/fail2ban.log sempre incluído se existir
     *
     * Retorna: [['label' => 'sshd', 'path' => '/var/log/auth.log'], ...]
     */
    /**
     * Logs bem conhecidos que são incluídos automaticamente se existirem no disco.
     * Permite que o Log Viewer funcione sem nenhuma configuração manual.
     */
    public const WELL_KNOWN_LOGS = [
        '/var/log/whmcs_auth.log'           => 'WHMCS Auth',
        '/var/log/apache2/access.log'        => 'Apache Access',
        '/var/log/apache2/whmcs_access.log'  => 'WHMCS Apache Access',
        '/var/log/apache2/error.log'         => 'Apache Error',
        '/var/log/auth.log'                  => 'Linux Auth (SSH/sudo)',
        '/var/log/syslog'                    => 'Syslog',
        '/var/log/nginx/access.log'          => 'Nginx Access',
        '/var/log/nginx/error.log'           => 'Nginx Error',
    ];

    public function getAvailableLogs(array $extra = []): array
    {
        $logs      = [];
        $seenPaths = [];

        // 1. Auto-descoberta: logs bem conhecidos que existem no disco
        foreach (self::WELL_KNOWN_LOGS as $path => $label) {
            if (file_exists($path) && $this->isValidPath($path) && !isset($seenPaths[$path])) {
                $logs[]           = ['label' => $label, 'path' => $path];
                $seenPaths[$path] = true;
            }
        }

        // 2. DB: custom_log.* — adicionados pelo admin via tela Log Paths
        try {
            $rows = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_config')
                ->where('key', 'like', 'custom_log.%')
                ->get();
            foreach ($rows as $row) {
                $label = substr($row->key, strlen('custom_log.'));
                if ($row->value && $this->isValidPath($row->value) && !isset($seenPaths[$row->value])) {
                    $logs[]                 = ['label' => $label, 'path' => $row->value];
                    $seenPaths[$row->value] = true;
                }
            }
        } catch (\Throwable $e) {}

        // 3. DB: logpath.* — legado (jails com logpath configurado)
        try {
            $rows = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_config')
                ->where('key', 'like', 'logpath.%')
                ->get();
            foreach ($rows as $row) {
                $jail = substr($row->key, strlen('logpath.'));
                if ($row->value && $this->isValidPath($row->value) && !isset($seenPaths[$row->value])) {
                    $logs[]                 = ['label' => $jail, 'path' => $row->value];
                    $seenPaths[$row->value] = true;
                }
            }
        } catch (\Throwable $e) {}

        // 4. jail.local: paths de jails não cobertos pelo DB
        foreach ($extra as $path => $label) {
            if (!isset($seenPaths[$path]) && $this->isValidPath($path)) {
                $logs[]           = ['label' => $label, 'path' => $path];
                $seenPaths[$path] = true;
            }
        }

        // 5. Sempre inclui fail2ban.log se existir
        $fb = '/var/log/fail2ban.log';
        if (file_exists($fb) && !isset($seenPaths[$fb])) {
            $logs[] = ['label' => 'fail2ban (geral)', 'path' => $fb];
        }

        return $logs;
    }

    /**
     * Lê as últimas N linhas de um arquivo de log.
     * Valida o path antes de abrir.
     * Retorna array de strings (sem newline).
     */
    public function readLines(string $path, int $lines = 100): array
    {
        if (!$this->isValidPath($path)) {
            return [];
        }
        if (!is_readable($path)) {
            return [];
        }

        $lines = max(10, min(500, $lines));

        // Leitura eficiente usando SplFileObject para arquivos grandes
        $file = new \SplFileObject($path, 'r');
        $file->seek(PHP_INT_MAX);
        $total = $file->key();

        $start = max(0, $total - $lines);
        $result = [];

        $file->seek($start);
        while (!$file->eof()) {
            $line = rtrim((string)$file->current(), "\r\n");
            if ($line !== '') {
                $result[] = $line;
            }
            $file->next();
        }

        return array_slice($result, -$lines);
    }

    /**
     * Extrai IPs (IPv4 e IPv6) de um array de linhas de log.
     * Retorna array associativo: ['ip' => 'linha_index', ...]
     * Na prática: [['ip' => '1.2.3.4', 'line_index' => 0], ...]
     */
    public function extractIPs(array $lines): array
    {
        $ipv4 = '\b(?:\d{1,3}\.){3}\d{1,3}\b';
        $ipv6 = '\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b';
        $pattern = '/(' . $ipv4 . '|' . $ipv6 . ')/';

        $found = [];
        foreach ($lines as $idx => $line) {
            if (preg_match_all($pattern, $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $found[] = ['ip' => $ip, 'line_index' => $idx];
                    }
                }
            }
        }
        return $found;
    }

    /**
     * Marca cada linha com classes CSS para highlight no front-end.
     * Retorna array: [['text' => '...', 'class' => 'normal|suspicious|error', 'ips' => [...]], ...]
     */
    public function highlightSuspicious(array $lines): array
    {
        $ipv4 = '\b(?:\d{1,3}\.){3}\d{1,3}\b';
        $ipv6 = '\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b';
        $ipPattern = '/(' . $ipv4 . '|' . $ipv6 . ')/';

        $result = [];
        foreach ($lines as $line) {
            $class = 'normal';

            // Verificar padrões de erro
            foreach (self::ERROR_PATTERNS as $p) {
                if (strpos($line, $p) !== false) {
                    $class = 'error';
                    break;
                }
            }

            // Verificar padrões suspeitos (sobrepõe 'error')
            foreach (self::SUSPICIOUS_PATTERNS as $p) {
                if (stripos($line, $p) !== false) {
                    $class = 'suspicious';
                    break;
                }
            }

            // Extrair IPs da linha
            $ips = [];
            if (preg_match_all($ipPattern, $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $ips[] = $ip;
                    }
                }
            }

            $result[] = [
                'text'  => $line,
                'class' => $class,
                'ips'   => array_unique($ips),
            ];
        }
        return $result;
    }

    /**
     * Valida se o path é seguro para leitura.
     * Não permite traversal, deve ser absoluto e extensão permitida.
     */
    public function isValidPath(string $path): bool
    {
        if (strpos($path, '..') !== false) {
            return false;
        }
        if (!str_starts_with($path, '/')) {
            return false;
        }
        // [SEC-8] Restringir leitura a diretórios de log conhecidos.
        // Impede que um admin configure /etc/passwd, /etc/shadow, chaves SSH etc.
        // como path de log, expondo arquivos sensíveis via fetch_lines AJAX.
        $allowedPrefixes = ['/var/log/', '/var/www/html/', '/tmp/'];
        foreach ($allowedPrefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }
        return false;
    }
}
