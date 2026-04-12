<?php
namespace AMS\Fail2Ban;

/**
 * AIAnalyzer — integração com a API Anthropic (Claude) para análise de logs.
 *
 * Segurança:
 * - Chave API nunca é logada ou impressa em HTML
 * - Logs enviados são truncados em 200 linhas
 * - Resposta JSON validada antes de usar
 */
class AIAnalyzer
{
    private string $apiKey;
    private string $model    = 'claude-sonnet-4-5';
    private string $endpoint = 'https://api.anthropic.com/v1/messages';

    /** Prompt padrão enviado ao Claude. Pode ser sobrescrito pelo banco. */
    private const DEFAULT_PROMPT = 'Você é um especialista em segurança de servidores Linux.
Analise as seguintes linhas de log do Apache/fail2ban e identifique ameaças.

Para cada ameaça encontrada, retorne APENAS um JSON array com os campos:
ip, threat, severity (low|medium|high|critical), confidence (0-100),
evidence (array de linhas relevantes), action (ban|monitor|whitelist),
jail, bantime (segundos), reason (em português), suggested_rule (jail.local entry).

Não inclua texto fora do JSON.

LOGS:
{logs}';

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * Envia as linhas de log para o Claude e retorna array de sugestões estruturadas.
     * Limita a 200 linhas para controle de custo.
     */
    public function analyze(array $logLines): array
    {
        if (empty($logLines)) {
            return [];
        }

        // Truncar em 200 linhas
        $logLines = array_slice($logLines, -200);

        $prompt   = $this->buildPrompt($logLines);
        $response = $this->callApi($prompt);

        if ($response === null) {
            return [];
        }

        return $this->parseResponse($response);
    }

    /**
     * Monta o prompt técnico enviado ao Claude.
     * Tenta carregar o prompt customizado do banco; usa o padrão como fallback.
     */
    public function buildPrompt(array $logLines): string
    {
        $promptTemplate = Database::getConfig('ai_prompt', self::DEFAULT_PROMPT);

        $logsText = implode("\n", $logLines);

        return str_replace('{logs}', $logsText, $promptTemplate);
    }

    /**
     * Retorna o prompt padrão (usado para popular o campo de edição na tela de config).
     */
    public static function getDefaultPrompt(): string
    {
        return self::DEFAULT_PROMPT;
    }

    /**
     * Testa a conectividade com a API Anthropic.
     * Envia uma mensagem mínima e verifica se a resposta é válida.
     */
    public function ping(): bool
    {
        $body = json_encode([
            'model'      => $this->model,
            'max_tokens' => 10,
            'messages'   => [
                ['role' => 'user', 'content' => 'ping'],
            ],
        ]);

        $raw = $this->httpPost($body);
        if ($raw === false) {
            return false;
        }

        $data = json_decode($raw, true);
        return isset($data['content']) || isset($data['id']);
    }

    // -----------------------------------------------------------------------
    // Privados
    // -----------------------------------------------------------------------

    /**
     * Chama a API Anthropic com o prompt montado.
     * Retorna o texto bruto da resposta do modelo, ou null em caso de erro.
     */
    private function callApi(string $prompt): ?string
    {
        $body = json_encode([
            'model'      => $this->model,
            'max_tokens' => 4096,
            'messages'   => [
                ['role' => 'user', 'content' => $prompt],
            ],
        ]);

        $raw = $this->httpPost($body);
        if ($raw === false) {
            return null;
        }

        $data = json_decode($raw, true);
        if (!isset($data['content'][0]['text'])) {
            return null;
        }

        return $data['content'][0]['text'];
    }

    /**
     * Executa o POST HTTP para a API Anthropic usando cURL.
     * Retorna o corpo da resposta ou false em caso de falha.
     */
    private function httpPost(string $body): string|false
    {
        if (!function_exists('curl_init')) {
            return false;
        }

        $ch = curl_init($this->endpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'x-api-key: ' . $this->apiKey,
                'anthropic-version: 2023-06-01',
            ],
        ]);

        $response = curl_exec($ch);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($error || $response === false) {
            return false;
        }

        return (string)$response;
    }

    /**
     * Faz parse da resposta JSON do Claude.
     * O Claude deve retornar apenas um JSON array — extrai e valida.
     */
    private function parseResponse(string $response): array
    {
        // Tenta extrair o JSON mesmo que haja texto extra
        if (preg_match('/\[[\s\S]*\]/s', $response, $matches)) {
            $decoded = json_decode($matches[0], true);
            if (is_array($decoded)) {
                return $this->sanitizeSuggestions($decoded);
            }
        }

        // Tenta decode direto
        $decoded = json_decode($response, true);
        if (is_array($decoded)) {
            return $this->sanitizeSuggestions($decoded);
        }

        return [];
    }

    /**
     * Sanitiza e valida cada sugestão retornada pelo Claude.
     * Garante que todos os campos obrigatórios existam e estejam em formato seguro.
     */
    private function sanitizeSuggestions(array $raw): array
    {
        $valid      = [];
        $severities = ['low', 'medium', 'high', 'critical'];
        $actions    = ['ban', 'monitor', 'whitelist'];

        foreach ($raw as $item) {
            if (!is_array($item)) {
                continue;
            }

            // IP obrigatório e válido
            $ip = trim($item['ip'] ?? '');
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            $severity = in_array($item['severity'] ?? '', $severities, true)
                ? $item['severity']
                : 'medium';

            $action = in_array($item['action'] ?? '', $actions, true)
                ? $item['action']
                : 'ban';

            $confidence = max(0, min(100, (int)($item['confidence'] ?? 0)));
            $bantime    = max(60, min(31536000, (int)($item['bantime'] ?? 3600)));

            $evidence = [];
            if (isset($item['evidence']) && is_array($item['evidence'])) {
                foreach ($item['evidence'] as $ev) {
                    $evidence[] = substr((string)$ev, 0, 500);
                }
            }

            $valid[] = [
                'ip'             => $ip,
                'threat'         => substr(strip_tags($item['threat'] ?? 'Ameaça desconhecida'), 0, 128),
                'severity'       => $severity,
                'confidence'     => $confidence,
                'evidence'       => $evidence,
                'action'         => $action,
                'jail'           => substr(preg_replace('/[^a-zA-Z0-9_-]/', '', $item['jail'] ?? ''), 0, 64),
                'bantime'        => $bantime,
                'reason'         => substr(strip_tags($item['reason'] ?? ''), 0, 1000),
                'suggested_rule' => substr($item['suggested_rule'] ?? '', 0, 4000),
            ];
        }

        return $valid;
    }
}
