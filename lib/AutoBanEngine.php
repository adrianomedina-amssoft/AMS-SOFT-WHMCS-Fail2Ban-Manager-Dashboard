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
     */
    public function runAnalysis(): array
    {
        $mode          = Database::getConfig('ai_mode', 'suggestion');
        $minConfidence = (int)Database::getConfig('ai_min_confidence', 75);
        $whitelist     = $this->getWhitelist();

        // Modo automático exige confirmação explícita do admin (segurança dupla)
        if (in_array($mode, ['auto', 'threshold'], true)) {
            if (Database::getConfig('ai_confirmed_auto', '0') !== '1') {
                return []; // Bloqueia execução até que o admin confirme na tela de configurações
            }
        }
        $viewer        = new LogViewer();
        $availableLogs = $viewer->getAvailableLogs();

        if (empty($availableLogs)) {
            return [];
        }

        $results = [];
        foreach ($availableLogs as $logInfo) {
            $lines       = $viewer->readLines($logInfo['path'], 200);
            $suggestions = $this->analyzer->analyze($lines);

            foreach ($suggestions as $suggestion) {
                // Ignorar IPs na whitelist
                if (in_array($suggestion['ip'], $whitelist, true)) {
                    continue;
                }

                // Ignorar abaixo do limiar de confiança
                if ($suggestion['confidence'] < $minConfidence) {
                    continue;
                }

                // Ignorar sugestões de ação != 'ban'
                if (($suggestion['action'] ?? 'ban') !== 'ban') {
                    continue;
                }

                switch ($mode) {
                    case 'auto':
                        $id = $this->saveSuggestion($suggestion, 'auto_executed');
                        $this->executeBan($suggestion);
                        $results[] = ['id' => $id, 'ip' => $suggestion['ip'], 'mode' => 'auto'];
                        break;

                    case 'threshold':
                        $id = $this->saveSuggestion($suggestion, 'pending');
                        if ($this->checkThresholdBySeverity($suggestion['ip'], $suggestion['severity'])) {
                            Database::updateSuggestionStatus($id, 'auto_executed');
                            $this->executeBan($suggestion);
                            $results[] = ['id' => $id, 'ip' => $suggestion['ip'], 'mode' => 'threshold_triggered'];
                        } else {
                            $results[] = ['id' => $id, 'ip' => $suggestion['ip'], 'mode' => 'threshold_waiting'];
                        }
                        break;

                    default: // suggestion
                        $id = $this->saveSuggestion($suggestion, 'pending');
                        $results[] = ['id' => $id, 'ip' => $suggestion['ip'], 'mode' => 'suggestion'];
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
    public function executeBan(array $suggestion, ?int $adminId = null): bool
    {
        $ip   = $suggestion['ip']   ?? '';
        $jail = $suggestion['jail'] ?? '';

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Se não há jail específico, tenta o padrão 'sshd'
        if (empty($jail)) {
            $jails = $this->client->getJails();
            $jail  = !empty($jails) ? $jails[0] : 'sshd';
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
