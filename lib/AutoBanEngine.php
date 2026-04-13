<?php
namespace AMS\Fail2Ban;

/**
 * AutoBanEngine — motor de ban automático baseado nas sugestões da IA.
 *
 * Modos de operação (configurado em ai_mode):
 *   suggestion  — IA sugere, admin aprova
 *   auto        — IA analisa e bane imediatamente
 *   threshold   — IA aguarda N detecções em X minutos por severidade
 */
class AutoBanEngine
{
    private AIAnalyzer    $analyzer;
    private Fail2BanClient $client;

    public function __construct(AIAnalyzer $analyzer, Fail2BanClient $client)
    {
        $this->analyzer = $analyzer;
        $this->client   = $client;
    }

    /**
     * Roda análise em todos os logs configurados no módulo.
     * Retorna array com resultados de cada log processado.
     *
     * Duas camadas de proteção contra trabalho redundante:
     *   1. Watermark por arquivo: lê apenas bytes novos desde a última análise.
     *   2. Deduplicação de IP: ignora IPs já conhecidos (pending/approved/auto_executed
     *      nos últimos 7 dias) — chamada à IA só ocorre para conteúdo genuinamente novo.
     */
    public function runAnalysis(): array
    {
        $mode          = Database::getConfig('ai_mode', 'suggestion');
        $minConfidence = (int)Database::getConfig('ai_min_confidence', 75);
        $whitelist     = $this->getWhitelist();

        // Modo automático exige confirmação explícita do admin (segurança dupla)
        if (in_array($mode, ['auto', 'threshold'], true)) {
            if (Database::getConfig('ai_confirmed_auto', '0') !== '1') {
                return [];
            }
        }

        $viewer        = new LogViewer();
        $availableLogs = $viewer->getAvailableLogs();

        if (empty($availableLogs)) {
            return [];
        }

        // Verificação em tempo real: IPs atualmente banidos no fail2ban.
        // Mais inteligente que dedup por tempo fixo: se o ban expirou ou foi
        // removido manualmente, o IP volta a ser detectado na próxima análise.
        $activeBannedIPs = [];
        try {
            if ($this->client->ping()) {
                $bannedData      = $this->client->getBannedIPs();
                $activeBannedIPs = array_column($bannedData, 'ip');
            }
        } catch (\Throwable $e) {
            // fail2ban offline — fallback para dedup baseado em tempo no banco
        }

        // IPs com sugestão pendente (admin ainda não agiu — não floodar a fila)
        $pendingIPs = Database::getPendingIPs();

        // Fallback quando fail2ban está offline: usa janela dinâmica baseada
        // no global_bantime em vez de fixar 7 dias
        if (empty($activeBannedIPs)) {
            $bantimeDays     = (int)ceil((int)Database::getConfig('global_bantime', 604800) / 86400);
            $activeBannedIPs = Database::getKnownIPs($bantimeDays);
        }

        // Lista combinada: banidos ativos + pendentes de revisão
        $skipIPs = array_unique(array_merge($activeBannedIPs, $pendingIPs));

        $results = [];

        foreach ($availableLogs as $logInfo) {
            $path = $logInfo['path'];

            if (!is_readable($path)) {
                continue;
            }

            $currentSize = @filesize($path);
            if ($currentSize === false) {
                continue;
            }

            // ── Watermark ────────────────────────────────────────────────────
            $offsetKey    = 'ai_log_offset.' . md5($path);
            $storedOffset = (int)Database::getConfig($offsetKey, 0);

            if ($currentSize === $storedOffset) {
                // Nenhum conteúdo novo — pular chamada à IA
                continue;
            }

            if ($currentSize < $storedOffset) {
                // Arquivo foi rotacionado/truncado — ler do início
                $storedOffset = 0;
            }

            $lines = $this->readNewLines($path, $storedOffset, 200);

            // Atualiza o watermark independentemente de haver sugestões
            Database::setConfig($offsetKey, (string)$currentSize);

            if (empty($lines)) {
                continue;
            }

            // ── Chamada à IA ─────────────────────────────────────────────────
            $suggestions = $this->analyzer->analyze($lines);

            foreach ($suggestions as $suggestion) {
                $ip = $suggestion['ip'] ?? '';

                // ── Filtros pré-salvamento ────────────────────────────────────

                // 1. Whitelist (filtrado ANTES da API — zero tokens gastos)
                if (in_array($ip, $whitelist, true)) {
                    continue;
                }

                // 2. IP atualmente banido no fail2ban ou com sugestão pendente
                if (in_array($ip, $skipIPs, true)) {
                    continue;
                }

                // 3. Confiança mínima
                if ($suggestion['confidence'] < $minConfidence) {
                    continue;
                }

                // 4. Apenas sugestões de ban
                if (($suggestion['action'] ?? 'ban') !== 'ban') {
                    continue;
                }

                // Dedup em memória: evita processar o mesmo IP duas vezes
                // no mesmo ciclo (múltiplos logs com o mesmo IP)
                $skipIPs[] = $ip;

                switch ($mode) {
                    case 'auto':
                        $id = $this->saveSuggestion($suggestion, 'auto_executed');
                        $this->executeBan($suggestion);
                        $results[] = ['id' => $id, 'ip' => $ip, 'mode' => 'auto'];
                        break;

                    case 'threshold':
                        $id = $this->saveSuggestion($suggestion, 'pending');
                        if ($this->checkThresholdBySeverity($ip, $suggestion['severity'])) {
                            Database::updateSuggestionStatus($id, 'auto_executed');
                            $this->executeBan($suggestion);
                            $results[] = ['id' => $id, 'ip' => $ip, 'mode' => 'threshold_triggered'];
                        } else {
                            $results[] = ['id' => $id, 'ip' => $ip, 'mode' => 'threshold_waiting'];
                        }
                        break;

                    default: // suggestion
                        $id = $this->saveSuggestion($suggestion, 'pending');
                        $results[] = ['id' => $id, 'ip' => $ip, 'mode' => 'suggestion'];
                        break;
                }
            }
        }

        return $results;
    }

    /**
     * Executa o ban de um IP via Fail2BanClient e registra no log de eventos.
     * adminId = null indica ban automático pela IA.
     */
    /** Nome da jail dedicada para bans manuais aprovados pela IA. */
    public const AI_JAIL = 'ai-bans';

    public function executeBan(array $suggestion, ?int $adminId = null): bool
    {
        $ip   = $suggestion['ip'] ?? '';
        $jail = self::AI_JAIL; // sempre usa a jail dedicada da IA

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $ok = $this->client->banIP($jail, $ip);

        if ($ok) {
            Database::logEvent(
                $ip,
                $jail,
                $adminId !== null ? 'manual_ban' : 'ban',
                'AI: ' . substr($suggestion['threat'] ?? 'auto-ban', 0, 240),
                $adminId
            );
        }

        return $ok;
    }

    /**
     * Verifica se o IP atingiu o threshold configurado para a severidade dada.
     */
    public function checkThresholdBySeverity(string $ip, string $severity): bool
    {
        $config = $this->parseThresholdConfig($severity);
        return $this->checkThreshold($ip, $config['minutes'], $config['detections']);
    }

    /**
     * Verifica se há pelo menos $minDetections ocorrências do IP
     * nos últimos $minutes minutos na tabela de sugestões.
     */
    public function checkThreshold(string $ip, int $minutes, int $minDetections): bool
    {
        $count = Database::countRecentDetections($ip, $minutes);
        return $count >= $minDetections;
    }

    /**
     * Salva uma sugestão no banco com o status fornecido.
     * Retorna o ID inserido.
     */
    public function saveSuggestion(array $suggestion, string $status = 'pending'): int
    {
        $suggestion['status'] = $status;
        return Database::saveSuggestion($suggestion);
    }

    /**
     * Aprova uma sugestão pendente: executa o ban e atualiza o status.
     */
    public function approveSuggestion(int $suggestionId, int $adminId): bool
    {
        $suggestion = Database::getSuggestion($suggestionId);
        if (!$suggestion) {
            return false;
        }
        if ($suggestion['status'] !== 'pending') {
            return false;
        }

        // Verificar whitelist antes de banir
        if (in_array($suggestion['ip'], $this->getWhitelist(), true)) {
            return false;
        }

        $ok = $this->executeBan($suggestion, $adminId);
        if ($ok) {
            Database::updateSuggestionStatus($suggestionId, 'approved', $adminId);
        }
        return $ok;
    }

    /**
     * Rejeita uma sugestão pendente (nunca executa ban).
     */
    public function rejectSuggestion(int $suggestionId, int $adminId): bool
    {
        $suggestion = Database::getSuggestion($suggestionId);
        if (!$suggestion || $suggestion['status'] !== 'pending') {
            return false;
        }
        return Database::updateSuggestionStatus($suggestionId, 'rejected', $adminId);
    }

    // -----------------------------------------------------------------------
    // Privados
    // -----------------------------------------------------------------------

    /**
     * Lê apenas as linhas novas de um arquivo a partir de $offset bytes.
     * Retorna no máximo $maxLines linhas (as mais recentes do trecho novo).
     *
     * Seguro contra log rotation: se o arquivo tiver sido truncado o caller
     * já terá resetado o offset para 0 antes de chamar este método.
     */
    private function readNewLines(string $path, int $offset, int $maxLines = 200): array
    {
        $viewer = new LogViewer();
        if (!$viewer->isValidPath($path) || !is_readable($path)) {
            return [];
        }

        $fp = @fopen($path, 'r');
        if (!$fp) {
            return [];
        }

        if ($offset > 0) {
            fseek($fp, $offset);
        }

        $content = stream_get_contents($fp);
        fclose($fp);

        if ($content === false || trim($content) === '') {
            return [];
        }

        $lines = array_values(array_filter(
            array_map('rtrim', explode("\n", $content)),
            fn ($l) => $l !== ''
        ));

        // Retorna apenas as últimas $maxLines linhas do trecho novo
        return array_slice($lines, -$maxLines);
    }

    /** Retorna a whitelist de IPs como array. */
    private function getWhitelist(): array
    {
        $raw = Database::getConfig('ai_whitelist_ips', '');
        if (empty($raw)) {
            return [];
        }
        $lines = preg_split('/[\r\n,]+/', $raw);
        $valid = [];
        foreach ($lines as $line) {
            $ip = trim($line);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid[] = $ip;
            }
        }
        return $valid;
    }

    /**
     * Lê a configuração de threshold para uma severidade.
     * Formato armazenado: "detections:minutes" (ex: "2:10")
     */
    private function parseThresholdConfig(string $severity): array
    {
        $defaults = [
            'critical' => ['detections' => 1, 'minutes' => 5],
            'high'     => ['detections' => 2, 'minutes' => 10],
            'medium'   => ['detections' => 5, 'minutes' => 30],
            'low'      => ['detections' => 10, 'minutes' => 60],
        ];

        $key = 'ai_threshold_' . $severity;
        $raw = Database::getConfig($key, '');

        if ($raw && preg_match('/^(\d+):(\d+)$/', $raw, $m)) {
            return ['detections' => (int)$m[1], 'minutes' => (int)$m[2]];
        }

        return $defaults[$severity] ?? ['detections' => 5, 'minutes' => 30];
    }
}
