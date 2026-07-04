<?php
namespace AMS\Fail2Ban;

/**
 * FilterManager — cria e gerencia filtros e jails fail2ban gerados pela IA.
 *
 * Princípio de isolamento: esta classe NÃO interage com aprovações de IP.
 * Criação de filtro/jail é sempre uma ação independente do ban de IP.
 *
 * Segurança:
 * - filter_name sanitizado: apenas [a-z0-9-], max 50 chars
 * - failregex validado com preg_match antes de gravar em arquivo
 * - path traversal prevenido com verificação de prefixo
 * - escrita atômica via /tmp + sudo cp
 * - jailExists() verifica 3 fontes independentes para evitar bug "jail existente"
 */
class FilterManager
{
    private string $filterDir;
    private JailConfig $jailConfig;
    private Fail2BanClient $client;

    public function __construct(string $filterDir, JailConfig $jailConfig, Fail2BanClient $client)
    {
        $this->filterDir  = rtrim($filterDir, '/') . '/';
        $this->jailConfig = $jailConfig;
        $this->client     = $client;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Verifica se o arquivo de filtro já existe em filter.d/.
     */
    public function filterExists(string $name): bool
    {
        $name = $this->sanitizeFilterName($name);
        if ($name === '') {
            return false;
        }
        return file_exists($this->filterDir . 'amsfb-' . $name . '.conf');
    }

    /**
     * Verifica se a jail já existe em 3 fontes independentes:
     * 1. jail.local (arquivo em disco)
     * 2. jail.d/*.conf (arquivos em disco)
     * 3. fail2ban daemon em memória (via fail2ban-client status)
     *
     * Se QUALQUER fonte confirmar existência, retorna true.
     * Isso evita o bug histórico de "jail existente" onde uma única
     * fonte de verificação deixava duplicatas passarem.
     */
    public function jailExists(string $name): bool
    {
        if ($name === '') {
            return false;
        }

        // Fonte 1: jail.local em disco
        $jailLocal = $this->jailConfig->readJailLocal();
        if (isset($jailLocal[$name])) {
            return true;
        }

        // Fonte 2: arquivos em /etc/fail2ban/jail.d/
        $jailDDir = dirname(rtrim($this->filterDir, '/')) . '/jail.d/';
        foreach (glob($jailDDir . '*.conf') ?: [] as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }
            if (preg_match('/^\s*\[' . preg_quote($name, '/') . '\]\s*$/m', $content)) {
                return true;
            }
        }

        // Fonte 3: daemon fail2ban em memória
        $activeJails = $this->client->getJails();
        if (in_array($name, $activeJails, true)) {
            return true;
        }

        return false;
    }

    /**
     * Cria o arquivo de filtro fail2ban em filter.d/.
     * Retorna true se criado com sucesso OU se já existia (idempotente).
     * Retorna false em caso de erro real (permissão, regex inválido, etc.).
     */
    public function createFilter(string $name, string $failregex, string $description): bool
    {
        $name = $this->sanitizeFilterName($name);
        if ($name === '') {
            return false;
        }

        if (!$this->validateFailregex($failregex)) {
            return false;
        }

        // Já existe — sucesso silencioso (idempotente)
        if ($this->filterExists($name)) {
            return true;
        }

        $dest = $this->filterDir . 'amsfb-' . $name . '.conf';

        // Proteção contra path traversal: o destino deve estar dentro de filterDir
        $destDir = dirname($dest);
        $realFilterDir = realpath($this->filterDir);
        $realDestDir   = $realFilterDir !== false
            ? $realFilterDir
            : $this->filterDir; // fallback se filterDir não existir
        if ($realFilterDir !== false && realpath($destDir) !== $realFilterDir) {
            return false;
        }

        // Montar conteúdo do arquivo no formato padrão fail2ban
        // Múltiplas linhas de failregex são indentadas — fail2ban compila cada uma separadamente
        $description = preg_replace('/[\x00-\x1F\x7F]/', '', $description);
        $failregexLines  = array_filter(array_map('trim', explode("\n", $failregex)));
        $failregexFormatted = implode("\n            ", $failregexLines);
        $content = "# AMS Fail2Ban Manager -- filtro gerado automaticamente\n"
                 . "# " . substr($description, 0, 200) . "\n"
                 . "# Criado em: " . date('Y-m-d H:i:s') . "\n\n"
                 . "[Definition]\n"
                 . "failregex = " . $failregexFormatted . "\n"
                 . "ignoreregex =\n";

        // Escrita atômica via arquivo temporário
        $tmp = tempnam(sys_get_temp_dir(), 'amsfb_filter_');
        if ($tmp === false) {
            return false;
        }

        if (file_put_contents($tmp, $content, LOCK_EX) === false) {
            @unlink($tmp);
            return false;
        }

        // Tenta cópia direta (funciona se filter.d for gravável pelo processo)
        if (@copy($tmp, $dest)) {
            @chmod($dest, 0644);
            @unlink($tmp);
            return true;
        }

        // Fallback: cópia via sudo (requer entradas no sudoers)
        $ok = $this->client->copySudoFile($tmp, $dest);
        @unlink($tmp);
        return $ok;
    }

    /**
     * Remove o arquivo de filtro fail2ban de filter.d/.
     * Idempotente: se não existir, retorna true.
     * Usado para limpar filtros órfãos (filtro criado mas jail falhou).
     */
    public function removeFilter(string $name): bool
    {
        $name = $this->sanitizeFilterName($name);
        if ($name === '') {
            return true;
        }

        $dest = $this->filterDir . 'amsfb-' . $name . '.conf';

        if (!file_exists($dest)) {
            return true; // já não existe — idempotente
        }

        // Tenta remoção direta
        if (@unlink($dest)) {
            return true;
        }

        // Fallback: remoção via sudo
        try {
            $tmp = sys_get_temp_dir() . '/amsfb_rm_' . md5($name);
            // Não existe comando sudo rm no sudoers — usar shell_exec como fallback
            // Se não conseguir, retorna false (log caller irá registrar)
            return false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Cria uma jail em jail.local usando o filtro recém-criado.
     * Retorna true se criada OU se já existia (idempotente).
     *
     * A verificação jailExists() usa 3 fontes, evitando o bug histórico
     * onde JailConfig::addJail() verificava apenas jail.local e deixava
     * passar jails já carregadas no daemon ou em jail.d/.
     *
     * $params aceita:
     *   'bantime'  => segundos (default 86400)
     *   'logpath'  => caminho do log a monitorar (auto-detectado se omitido)
     */
    public function createJailForFilter(string $jailName, string $filterName, array $params): bool
    {
        // Verificação tripla antes de qualquer escrita
        if ($this->jailExists($jailName)) {
            return true; // já existe — sucesso silencioso
        }

        $filterName = $this->sanitizeFilterName($filterName);
        if ($filterName === '') {
            return false;
        }

        $logpath = $params['logpath'] ?? '';
        if (empty($logpath)) {
            $logpath = $this->discoverLogPath();
        }

        $jailParams = [
            'enabled'  => 'true',
            'filter'   => 'amsfb-' . $filterName,
            'maxretry' => '3',
            'findtime' => '3600',
            'bantime'  => (string)(int)($params['bantime'] ?? 86400),
            'logpath'  => $logpath,
            'ignoreip' => '127.0.0.1',
        ];

        // JailConfig::addJail() tem sua própria verificação de jail.local
        // como camada adicional de proteção
        $ok = $this->jailConfig->addJail($jailName, $jailParams);
        if ($ok) {
            return true;
        }

        // addJail() retornou false — pode ser corrida (TOCTOU) onde outro
        // processo criou a jail entre nossa verificação e nossa escrita.
        // Re-verificar: se a jail existe agora, não é erro — é sucesso.
        return $this->jailExists($jailName);
    }

    /**
     * Descobre o log path mais adequado verificando arquivos existentes no disco.
     * Preferência: WHMCS auth > Apache error > Apache access > syslog.
     */
    private function discoverLogPath(): string
    {
        $candidates = [
            '/var/log/whmcs_auth.log',
            '/var/log/apache2/error.log',
            '/var/log/apache2/access.log',
            '/var/log/auth.log',
            '/var/log/syslog',
        ];
        foreach ($candidates as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }
        return '/var/log/apache2/error.log'; // fallback absoluto
    }

    /**
     * Recarrega uma jail específica, com fallback para reload geral.
     * Falha no reload é não-fatal — retorna false mas não lança exceção.
     */
    public function reloadJail(string $jailName): bool
    {
        // Tenta reload específico da jail
        if ($this->client->reload($jailName)) {
            return true;
        }
        // Fallback: reload completo do fail2ban
        return $this->client->reload();
    }

    // -----------------------------------------------------------------------
    // Deduplicação por similaridade
    // -----------------------------------------------------------------------

    /**
     * Busca filtro existente com failregex similar ao informado.
     * Normaliza os regex antes de comparar (remove <HOST>, escapes, delimitadores)
     * e compara tokens/palavras-chave.
     *
     * Retorna ['name' => '...', 'similarity' => 0.0-1.0, 'failregex' => '...'] ou null se nada similar.
     * O campo 'failregex' é o regex do filtro existente — usado em logs de auditoria.
     */
    public function findSimilarFilter(string $failregex): ?array
    {
        $inputTokens = self::tokenizeFailregex($failregex);
        if (empty($inputTokens)) {
            return null;
        }

        $bestMatch   = null;
        $bestScore   = 0.0;
        $bestRegex   = '';

        foreach (glob($this->filterDir . 'amsfb-*.conf') ?: [] as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            // Extrair failregex do arquivo
            if (!preg_match('/^failregex\s*=\s*(.+)$/m', $content, $m)) {
                continue;
            }
            $existingRegex = trim($m[1]);

            $existingTokens = self::tokenizeFailregex($existingRegex);
            if (empty($existingTokens)) {
                continue;
            }

            // Calcular similaridade por interseção de tokens
            $intersection = array_intersect($inputTokens, $existingTokens);
            $union        = array_unique(array_merge($inputTokens, $existingTokens));
            $similarity   = count($union) > 0 ? count($intersection) / count($union) : 0;

            if ($similarity > $bestScore) {
                $bestScore = $similarity;
                $bestMatch = str_replace(['amsfb-', '.conf'], '', basename($file));
                $bestRegex = $existingRegex;
            }
        }

        if ($bestScore >= 0.5 && $bestMatch !== null) {
            return [
                'name'       => $bestMatch,
                'similarity' => round($bestScore, 2),
                'failregex'  => $bestRegex,
            ];
        }

        return null;
    }

    /**
     * Normaliza failregex para comparação de tokens.
     * Remove: <HOST>, delimitadores ^ $, escapes \, caracteres especiais de regex.
     * Extrai: palavras-chave (paths, status codes, user-agents, strings literais).
     */
    private static function tokenizeFailregex(string $regex): array
    {
        // Normalizar
        $norm = $regex;
        $norm = str_replace('<HOST>', '', $norm);
        $norm = str_replace(['^', '$', '\\'], '', $norm);
        $norm = preg_replace('/\(\?:.*?\)/', '', $norm); // non-capturing groups
        $norm = preg_replace('/\(\?P<.*?>/', '', $norm);  // named groups
        $norm = preg_replace('/\[.*?\]/', '', $norm);     // character classes
        $norm = preg_replace('/[+*?{}()|]/', ' ', $norm); // quantifiers e alternation
        $norm = preg_replace('/\d+/', ' ', $norm);        // números
        $norm = strtolower($norm);

        // Extrair tokens significativos (3+ chars)
        $tokens = preg_split('/[\s\/._-]+/', $norm, -1, PREG_SPLIT_NO_EMPTY);
        $tokens = array_filter($tokens, fn ($t) => strlen($t) >= 3);

        return array_values(array_unique($tokens));
    }

    // -----------------------------------------------------------------------
    // Privados
    // -----------------------------------------------------------------------

    /**
     * Sanitiza o nome do filtro: apenas [a-z0-9-], max 50 chars.
     * Converte para minúsculas e remove caracteres inválidos.
     */
    private function sanitizeFilterName(string $name): string
    {
        $name = strtolower($name);
        $name = preg_replace('/[^a-z0-9-]/', '', $name);
        $name = preg_replace('/-+/', '-', $name);
        $name = trim($name, '-');
        return substr($name, 0, 50);
    }

    /**
     * Valida a sintaxe do failregex usando preg_match() do PHP.
     * Cada linha é validada individualmente — fail2ban compila cada linha
     * como uma regex Python separada.
     *
     * Rejeita linhas com múltiplos <HOST> num mesmo padrão: o Python re module
     * não permite redefinição de grupos nomeados (ip4, ip6, dns) gerados pela
     * expansão de <HOST>, causando "redefinition of group name" e crash do servidor.
     */
    private function validateFailregex(string $failregex): bool
    {
        if (strlen($failregex) > 5000 || trim($failregex) === '') {
            return false;
        }

        // Validar cada linha separadamente (fail2ban compila cada linha como regex distinta)
        $lines = array_filter(array_map('trim', explode("\n", $failregex)));
        if (empty($lines)) {
            return false;
        }

        foreach ($lines as $line) {
            // Múltiplos <HOST> numa linha = grupos nomeados duplicados no Python re = crash fatal
            if (substr_count($line, '<HOST>') > 1) {
                return false;
            }

            $testRegex = str_replace('<HOST>', '1\\.2\\.3\\.4', $line);
            $escaped   = str_replace('/', '\\/', $testRegex);
            if (@preg_match('/' . $escaped . '/', '') === false) {
                return false;
            }
        }

        return true;
    }

    // -----------------------------------------------------------------------
    // Detecção segura de logpath (com allowlist)
    // -----------------------------------------------------------------------

    /** Logs permitidos para auto-criação de jail (allowlist de segurança). */
    private const ALLOWED_LOGS = [
        '/var/log/whmcs_auth.log',
        '/var/log/apache2/error.log',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error_whmcs.log',
        '/var/log/apache2/access_whmcs.log',
        '/var/log/auth.log',
        '/var/log/fail2ban.log',
    ];

    /** Retorna a allowlist de logs permitidos. */
    public static function getAllowedLogs(): array
    {
        return self::ALLOWED_LOGS;
    }

    /**
     * Versão segura de detectLogPath(): valida contra allowlist de logs permitidos.
     * Retorna null se o logpath inferido não estiver no allowlist ou se o fallback
     * genérico não corresponder ao tipo de ataque (evita jail monitorando log errado).
     *
     * Usado tanto pelo fluxo automático (AutoBanEngine) quanto pelo manual (AIController).
     *
     * @param string       $failregex    Failregex da sugestão
     * @param array|string $evidenceJson Evidence como string JSON ou array já decodificado
     * @param string       $filterName   Nome do filtro (para matchLog)
     */
    public function detectLogPathSafe(string $failregex, array|string $evidenceJson, string $filterName = ''): ?string
    {
        // Normalizar: garantir string JSON (caller pode passar array já decodificado)
        if (is_array($evidenceJson)) {
            $evidenceJson = json_encode($evidenceJson);
        }
        $inferred = $this->detectLogPath($failregex, $evidenceJson);

        if (in_array($inferred, self::ALLOWED_LOGS, true) && file_exists($inferred)) {
            return $inferred;
        }

        // Fallback genérico: só usar se o tipo de ataque fizer sentido para esse log
        $fallback = '/var/log/whmcs_auth.log';
        if (file_exists($fallback) && $this->attackMatchesLog($filterName, $fallback)) {
            return $fallback;
        }

        return null; // cai para ai-bans — melhor que jail inútil
    }

    /**
     * Detecta o logpath mais provável baseado no failregex e evidências.
     *
     * @param string       $failregex
     * @param array|string $evidenceJson  Evidence como string JSON ou array já decodificado
     */
    private function detectLogPath(string $failregex, array|string $evidenceJson): string
    {
        // Normalizar array para string JSON
        if (is_array($evidenceJson)) {
            $evidenceJson = json_encode($evidenceJson);
        }
        $evidenceLines = [];
        if (!empty($evidenceJson) && is_string($evidenceJson)) {
            $decoded = json_decode($evidenceJson, true);
            $evidenceLines = is_array($decoded) ? $decoded : [$evidenceJson];
        }

        $allText = strtolower($failregex . ' ' . implode(' ', $evidenceLines));

        if (strpos($allText, 'whmcs') !== false || strpos($allText, 'login failed') !== false) {
            if (file_exists('/var/log/whmcs_auth.log')) {
                return '/var/log/whmcs_auth.log';
            }
        }

        if (strpos($allText, 'ah0') !== false || strpos($allText, 'authz') !== false || strpos($allText, 'client denied') !== false) {
            if (file_exists('/var/log/apache2/error.log')) {
                return '/var/log/apache2/error.log';
            }
        }

        if (strpos($allText, 'sshd') !== false || strpos($allText, 'invalid user') !== false || strpos($allText, 'failed password') !== false) {
            if (file_exists('/var/log/auth.log')) {
                return '/var/log/auth.log';
            }
        }

        foreach (self::ALLOWED_LOGS as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return '/var/log/apache2/error.log';
    }

    /**
     * Verifica se o tipo de ataque (filter_name) faz sentido para o log indicado.
     * Evita criar jail "apache-scan" monitorando whmcs_auth.log.
     */
    private function attackMatchesLog(string $filterName, string $logPath): bool
    {
        $name = strtolower($filterName);

        // Ataques Apache/error log
        $apacheKeywords = ['apache', 'scan', 'rce', 'probe', 'exploit', 'bot', 'crawler',
            'vuln', 'sqli', 'injection', 'traversal', 'shell', 'webshell',
            'zgrab', 'hakai', 'boaform', 'druid', 'git-probe', 'autoindex',
            'malformed', 'protocol', 'directory', 'sensitive', 'phpunit',
            'actuator', 'hnap', 'redlion', 'reportserver', 'mglndd'];

        // Ataques WHMCS/auth log
        $whmcsKeywords = ['whmcs', 'login', 'brute', 'cart', 'invoice', 'mercadopago',
            'payment', 'checkout', 'password', 'credential', 'account',
            'token', 'gateway', 'pix', 'sync'];

        // Se o log é whmcs_auth.log, só aceitar ataques WHMCS
        if (strpos($logPath, 'whmcs_auth') !== false) {
            foreach ($whmcsKeywords as $kw) {
                if (strpos($name, $kw) !== false) {
                    return true;
                }
            }
            return false;
        }

        // Se o log é Apache, só aceitar ataques Apache
        if (strpos($logPath, 'apache') !== false) {
            foreach ($apacheKeywords as $kw) {
                if (strpos($name, $kw) !== false) {
                    return true;
                }
            }
            return false;
        }

        // Outros logs (auth.log, etc.) — aceitar qualquer ataque
        return true;
    }
}
