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
        ];

        // JailConfig::addJail() tem sua própria verificação de jail.local
        // como camada adicional de proteção
        return $this->jailConfig->addJail($jailName, $jailParams);
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
        if (strlen($failregex) > 1000 || trim($failregex) === '') {
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
}
