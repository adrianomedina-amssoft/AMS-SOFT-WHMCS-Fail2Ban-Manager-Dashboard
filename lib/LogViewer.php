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
     * Retorna todos os logs configurados no módulo.
     * Lê as chaves `logpath.*` da tabela mod_amssoft_fail2ban_config.
     * Retorna: [['label' => 'sshd', 'path' => '/var/log/auth.log'], ...]
     */
    public function getAvailableLogs(): array
    {
        $rows = \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_config')
            ->where('key', 'like', 'logpath.%')
            ->get();

        $logs = [];
        foreach ($rows as $row) {
            $jail = substr($row->key, strlen('logpath.'));
            if ($row->value && $this->isValidPath($row->value)) {
                $logs[] = ['label' => $jail, 'path' => $row->value];
            }
        }

        // Se não há nenhum configurado, oferece o log padrão do fail2ban
        if (empty($logs)) {
            $default = '/var/log/fail2ban.log';
            if (file_exists($default)) {
                $logs[] = ['label' => 'fail2ban', 'path' => $default];
            }
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
    private function isValidPath(string $path): bool
    {
        if (strpos($path, '..') !== false) {
            return false;
        }
        if (!str_starts_with($path, '/')) {
            return false;
        }
        // Permite qualquer extensão — logs podem ser .log, .txt, sem extensão, etc.
        // A proteção real é via sudo/permissões de sistema
        return true;
    }
}
