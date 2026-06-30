<?php
namespace AMS\Fail2Ban;

/**
 * GeoIP — lookup de dados geográficos via ip-api.com com cache e rate limiting.
 *
 * Endereço da API: http://ip-api.com/json/{ip}
 * Rate limit: 45 req/min (HTTP, não-HTTPS)
 * Timeout: 3 segundos por request
 */
class GeoIP
{
    private const API_URL = 'http://ip-api.com/json/%s?fields=status,message,countryCode,country,regionName,isp,as';
    private const TIMEOUT = 3; // segundos

    /** Máximo de HTTP requests por carregamento de página */
    public const MAX_REQUESTS_PER_CALL = 10;

    /** Limite seguro de requests por minuto (abaixo dos 45 da API) */
    public const RATE_LIMIT_SAFETY = 40;

    /** TTL do cache em dias */
    public const CACHE_TTL_DAYS = 30;

    // -----------------------------------------------------------------------
    // Lookup individual
    // -----------------------------------------------------------------------

    /**
     * Faz lookup de um único IP. Primeiro verifica cache, depois consulta a API.
     *
     * @return array|null Dados geo ou null se indisponível.
     *   ['country'=>'Brazil', 'country_code'=>'BR', 'region'=>'São Paulo',
    'isp'=>'Claro', 'asn'=>'AS28573 ...']
     */
    public static function lookup(string $ip): ?array
    {
        $result = self::bulkLookup([$ip]);
        return $result[$ip] ?? null;
    }

    // -----------------------------------------------------------------------
    // Bulk lookup com cache + rate limiting
    // -----------------------------------------------------------------------

    /**
     * Lookup em batch de múltiplos IPs. Cache-first, HTTP só para não cacheados.
     *
     * Fluxo:
     * 1. Consulta cache (1 query WHERE IN)
     * 2. Verifica rate limit global
     * 3. Para IPs não cacheados: HTTP requests (máximo batchLimit)
     * 4. Upsert resultados no cache
     * 5. Merge cache hits + novos resultados
     *
     * @param array $ips Lista de IPs a consultar
     * @return array Keyado por IP: ['1.2.3.4' => [...], ...]
     *   IPs não lookupados (rate limit ou erro) ficam com null no array.
     */
    public static function bulkLookup(array $ips): array
    {
        if (empty($ips)) {
            return [];
        }

        // Validar e deduplicar IPs
        $validIps = [];
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && !isset($validIps[$ip])) {
                $validIps[$ip] = true;
            }
        }
        $uniqueIps = array_keys($validIps);

        if (empty($uniqueIps)) {
            return [];
        }

        // Passo 1: consultar cache
        $cached = Database::getGeoCache($uniqueIps, self::CACHE_TTL_DAYS);

        // Identificar IPs não cacheados
        $missing = [];
        foreach ($uniqueIps as $ip) {
            if (!isset($cached[$ip])) {
                $missing[] = $ip;
            }
        }

        // Se todos estão no cache, retornar diretamente
        if (empty($missing)) {
            return $cached;
        }

        // Passo 2: verificar rate limit global
        //
        // ⚠️ Race condition conhecida: o estado (requests_this_minute, window_start)
        // é lido e escrito sem lock. Dois admins simultâneos podem ler o mesmo valor,
        // incrementar, e escrever — resultando em alguns requests acima do limite real.
        // Em produção com 1-2 admins, pior caso: 2-3 requests extras perto de 45.
        // A margem de segurança (40 em vez de 45) e o cooldown de 429 cobrem este caso.
        $rateState = Database::getGeoRateState();
        $now       = time();

        // Cooldown de 429: se a API retornou rate limit recentemente, não fazer nenhum request
        $cooldownUntil = (int) ($rateState['cooldown_until'] ?? 0);
        if ($cooldownUntil > $now) {
            return $cached;
        }

        // Se a janela de 60s expirou, resetar contador
        if ($rateState['minute_window_start'] == 0 || ($now - $rateState['minute_window_start']) >= 60) {
            $rateState['requests_this_minute'] = 0;
            $rateState['minute_window_start']  = $now;
        }

        $remaining   = max(0, self::RATE_LIMIT_SAFETY - $rateState['requests_this_minute']);
        $batchLimit  = min($remaining, self::MAX_REQUESTS_PER_CALL);

        if ($batchLimit <= 0) {
            // Rate limit atingido — retornar apenas o cache
            return $cached;
        }

        // Passo 3: HTTP requests para IPs não cacheados
        $toLookup   = array_slice($missing, 0, $batchLimit);
        $newEntries = [];

        foreach ($toLookup as $ip) {
            $data = self::fetchFromApi($ip);

            // Incrementar contador e atualizar janela
            $rateState['requests_this_minute']++;
            if ($rateState['minute_window_start'] === 0) {
                $rateState['minute_window_start'] = $now;
            }

            if ($data !== null) {
                $newEntries[] = $data;
                $cached[$ip]  = $data;
            }
            // Se null (erro/timeout), o IP fica sem dado — próxima visita tenta novamente
        }

        // Atualizar estado do rate limit no banco
        Database::setGeoRateState($rateState['requests_this_minute'], $rateState['minute_window_start']);

        // Passo 4: salvar novos resultados no cache
        if (!empty($newEntries)) {
            Database::setGeoCacheBatch($newEntries);
        }

        return $cached;
    }

    // -----------------------------------------------------------------------
    // Teste de conectividade
    // -----------------------------------------------------------------------

    /**
     * Testa se a API está acessível. Usa IP fixo 8.8.8.8 para não consumir
     * quota de um IP "novo" que poderia ser cacheado com dado real.
     *
     * @return bool true se a API respondeu com sucesso
     */
    public static function isAvailable(): bool
    {
        $data = self::fetchFromApi('8.8.8.8');
        return $data !== null;
    }

    /**
     * Retorna status informativo para a UI.
     */
    public static function getStatus(): array
    {
        $rateState = Database::getGeoRateState();
        $now       = time();

        // Recalcular janela se expirou
        $requestsThisMinute = $rateState['requests_this_minute'];
        if ($now - $rateState['minute_window_start'] >= 60) {
            $requestsThisMinute = 0;
        }

        $cooldownUntil = (int) ($rateState['cooldown_until'] ?? 0);
        $inCooldown    = $cooldownUntil > $now;

        return [
            'api_url'              => 'ip-api.com',
            'requests_this_minute' => $requestsThisMinute,
            'requests_remaining'   => $inCooldown ? 0 : max(0, self::RATE_LIMIT_SAFETY - $requestsThisMinute),
            'cache_ttl_days'       => self::CACHE_TTL_DAYS,
            'in_cooldown'          => $inCooldown,
            'cooldown_until'       => $cooldownUntil,
        ];
    }

    // -----------------------------------------------------------------------
    // Cache management
    // -----------------------------------------------------------------------

    /** Limpa todo o cache geo. */
    public static function clearCache(): void
    {
        Database::clearGeoCache();
    }

    // -----------------------------------------------------------------------
    // Helper: country code → emoji flag
    // -----------------------------------------------------------------------

    /**
     * Converte ISO 3166-1 alpha-2 para emoji de bandeira.
     * Usa Unicode Regional Indicator Symbols — funciona para qualquer país.
     *
     * @param string $countryCode Código de 2 letras (ex: "BR", "US")
     * @return string Emoji da bandeira ou 🌐 se inválido
     */
    public static function countryToFlag(string $countryCode): string
    {
        $countryCode = strtoupper(trim($countryCode));
        if (strlen($countryCode) !== 2) {
            return '🌐';
        }
        $offset = 0x1F1E6 - ord('A');
        return mb_chr($offset + ord($countryCode[0]), 'UTF-8')
             . mb_chr($offset + ord($countryCode[1]), 'UTF-8');
    }

    /**
     * Formata dados geo para exibição abaixo do IP.
     * Exemplo: "🇧🇷 São Paulo — Claro NXT"
     *
     * @param array|null $geo Dados geo (de lookup/bulkLookup) ou null
     * @return string Texto formatado ou "—" se indisponível
     */
    public static function formatGeo(?array $geo): string
    {
        if ($geo === null) {
            return '—';
        }

        $parts = [];

        // Bandeira + país
        if (!empty($geo['country_code'])) {
            $parts[] = self::countryToFlag($geo['country_code']);
        }
        if (!empty($geo['country'])) {
            $parts[] = $geo['country'];
        }

        // Região (se diferente do país)
        if (!empty($geo['region']) && $geo['region'] !== ($geo['country'] ?? '')) {
            $parts[] = $geo['region'];
        }

        // ISP
        if (!empty($geo['isp'])) {
            $parts[] = '— ' . $geo['isp'];
        }

        if (empty($parts)) {
            return '—';
        }

        return implode(' ', $parts);
    }

    // -----------------------------------------------------------------------
    // Interno: request HTTP para a API
    // -----------------------------------------------------------------------

    /**
     * Faz request HTTP para ip-api.com para um único IP.
     *
     * @return array|null Dados geo ou null em caso de erro/timeout.
     *   ['country'=>'Brazil', 'country_code'=>'BR', 'region'=>'São Paulo',
    'isp'=>'Claro', 'asn'=>'AS28573 ...']
     */
    private static function fetchFromApi(string $ip): ?array
    {
        // Validar IP antes de fazer request externo
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        // Não enviar IPs privados/reserved/loopback à API — economiza HTTP request e rate limit
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false
            || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false) {
            return null;
        }

        $url = sprintf(self::API_URL, urlencode($ip));

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return null;
        }

        // HTTP 429 (rate limit da API) — persistir cooldown de 60s no banco
        if ($httpCode === 429) {
            $rateState = Database::getGeoRateState();
            Database::setGeoRateState(
                $rateState['requests_this_minute'],
                $rateState['minute_window_start'],
                time() + 60  // cooldown_until: bloqueia requests por 60s
            );
            return null;
        }

        if ($httpCode !== 200) {
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data)) {
            return null;
        }

        // A API retorna {status: "success", ...} ou {status: "fail", message: "..."}
        if (($data['status'] ?? '') !== 'success') {
            return null;
        }

        // Separar campo "as" (ex: "AS28573 Claro NXT Telecomunicacoes Ltda")
        // em asn ("AS28573") e fallback para ISP se isp estiver vazio
        $asField = $data['as'] ?? '';
        $asn     = '';
        $isp     = $data['isp'] ?? '';
        if ($asField !== '') {
            // Extrair ASN: primeira palavra que começa com "AS" + dígitos
            if (preg_match('/^(AS\d+)/i', $asField, $m)) {
                $asn = strtoupper($m[1]);
            }
            // Fallback: se ISP vazio, usar o nome do AS (tudo após o ASN)
            if ($isp === '') {
                $isp = trim(preg_replace('/^AS\d+\s*/i', '', $asField));
            }
        }

        return [
            'ip'           => $ip,
            'country'      => $data['country']    ?? null,
            'country_code' => $data['countryCode'] ?? null,
            'region'       => $data['regionName']  ?? null,
            'isp'          => $isp !== '' ? $isp : null,
            'asn'          => $asn !== '' ? $asn : null,
        ];
    }
}
