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
        '/var/log/whmcs_auth.log'             => 'WHMCS Auth',
        '/var/log/apache2/access.log'          => 'Apache Access',
        '/var/log/apache2/error.log'           => 'Apache Error',
        '/var/log/apache2/access_whmcs.log'    => 'WHMCS Apache Access',
        '/var/log/apache2/error_whmcs.log'     => 'WHMCS Apache Error',
        '/var/log/apache2/whmcs_access.log'    => 'WHMCS Apache Access (alt)',
        '/var/log/auth.log'                    => 'Linux Auth (SSH/sudo)',
        '/var/log/syslog'                      => 'Syslog',
        '/var/log/nginx/access.log'            => 'Nginx Access',
        '/var/log/nginx/error.log'             => 'Nginx Error',
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

        $lines = max(10, min(1000, $lines));

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
     * Lê linhas novas de um arquivo a partir de um offset em bytes.
     * Usado pelo watermark para não reenviar logs já analisados.
     *
     * Seguro contra log rotation: se o arquivo foi truncado/rotacionado
     * (tamanho < offset), o caller deve resetar offset para 0 antes de chamar.
     *
     * @param string $path     Path do arquivo (validado internamente)
     * @param int    $offset   Byte offset para iniciar a leitura
     * @param int    $maxLines Máximo de linhas a retornar
     * @return array           ['lines' => array, 'offset' => int] — linhas lidas e offset real onde parou
     */
    public function readNewLinesFromOffset(string $path, int $offset, int $maxLines = 200): array
    {
        $empty = ['lines' => [], 'offset' => $offset];

        if (!$this->isValidPath($path) || !is_readable($path)) {
            return $empty;
        }

        $maxLines = max(10, min(1000, $maxLines));

        // Proteção contra offset inválido (ex: caller não verificou filesize)
        if ($offset > 0) {
            $fileSize = @filesize($path);
            if ($fileSize !== false && $offset > $fileSize) {
                $offset = 0; // fallback: ler do início
            }
        }

        $fp = @fopen($path, 'r');
        if (!$fp) {
            return $empty;
        }

        if ($offset > 0) {
            fseek($fp, $offset);
        }

        // Ler linha por linha, capturando offset real com ftell().
        // ftell() é preciso com \r\n e multi-byte UTF-8 (não cálculo manual).
        $lines = [];
        $realOffset = $offset;

        while (!feof($fp) && count($lines) < $maxLines) {
            $line = fgets($fp);
            if ($line === false) {
                break;
            }
            $line = rtrim($line, "\r\n");
            if ($line !== '') {
                $lines[] = $line;
            }
            $realOffset = ftell($fp);
        }

        fclose($fp);

        // Se leu até o final do arquivo (menos linhas que o max),
        // usar filesize como offset para evitar re-leitura no próximo ciclo.
        $fileSize = @filesize($path);
        if ($fileSize !== false && $realOffset >= $fileSize) {
            $realOffset = $fileSize;
        }

        return ['lines' => $lines, 'offset' => $realOffset];
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
     * Remove linhas cujos IPs estão todos na lista de skip.
     * Mantém linhas sem IP (podem ter padrões de ataque) e linhas
     * com pelo menos 1 IP fora da lista de skip.
     *
     * Whitelist pre-filter: evita enviar à IA linhas cujos IPs são todos
     * whitelisted/banidos/pendentes, economizando tokens.
     *
     * @param array $lines    Linhas de log
     * @param array $skipIPs  IPs a filtrar (whitelist + banidos + pendentes)
     * @return array           Linhas filtradas (re-indexadas)
     */
    public static function filterLinesByIPs(array $lines, array $skipIPs): array
    {
        if (empty($skipIPs) || empty($lines)) {
            return $lines;
        }

        $skipSet = array_flip($skipIPs); // O(1) lookup

        $ipv4 = '\b(?:\d{1,3}\.){3}\d{1,3}\b';
        $ipv6 = '\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b';
        $pattern = '/(' . $ipv4 . '|' . $ipv6 . ')/';

        $filtered = [];

        foreach ($lines as $line) {
            if (!preg_match_all($pattern, $line, $matches)) {
                // Sem IP — manter (pode ter padrão de ataque)
                $filtered[] = $line;
                continue;
            }

            $hasRelevantIP = false;
            foreach ($matches[1] as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) && !isset($skipSet[$ip])) {
                    $hasRelevantIP = true;
                    break;
                }
            }

            if ($hasRelevantIP) {
                $filtered[] = $line;
            }
            // else: todos os IPs da linha são whitelisted/banidos → remover
        }

        return $filtered;
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
