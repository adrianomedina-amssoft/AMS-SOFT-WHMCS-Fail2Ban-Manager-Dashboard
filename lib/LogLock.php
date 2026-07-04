<?php
namespace AMS\Fail2Ban;

/**
 * LogLock — lock de arquivo compartilhado entre cron (root) e painel (www-data).
 *
 * Resolve o bug onde lock files criados por root (644) não podiam ser
 * abertos por www-data, causando falso "analysis_locked".
 *
 * Usa diretório dedicado data/locks/ (dentro do projeto) com setgid para
 * que ambos os processos (root via cron, www-data via painel) consigam
 * criar e abrir lock files.
 */
class LogLock
{
    /** Diretório de lock dentro do projeto (data/locks/). */
    private static function lockDir(): string
    {
        return dirname(__DIR__) . '/data/locks/';
    }

    /**
     * Adquire lock exclusivo não-bloqueante para um arquivo de log.
     *
     * @param string $logPath  Path do arquivo de log
     * @return array{fp: resource|null, reason: string|null}
     *         fp = file pointer com lock, ou null se falhou
     *         reason = motivo da falha ('fopen_failed'|'locked_by_other'), ou null se OK
     */
    public static function acquire(string $logPath): array
    {
        $canonical = realpath($logPath) ?: $logPath;
        $lockDir   = self::lockDir();
        $lockFile  = $lockDir . 'log_' . md5($canonical) . '.lock';

        // Garantir diretório existe (idempotente, seguro para concorrência)
        if (!is_dir($lockDir)) {
            @mkdir($lockDir, 0770, true);
            // Tentar chgrp — funciona se o processo for root (cron)
            // Se for www-data (painel), já é dono do diretório pai
            @chgrp($lockDir, self::detectWebGroup());
            @chmod($lockDir, 2770); // setgid: herda grupo do diretório
        }

        // Criar arquivo se não existe (touch respeita setgid do diretório)
        if (!file_exists($lockFile)) {
            @touch($lockFile);
            // setgid do diretório herda grupo, mas chmod garante 660
            @chmod($lockFile, 0660);
        }

        $fp = @fopen($lockFile, 'c');
        if (!$fp) {
            return ['fp' => null, 'reason' => 'fopen_failed'];
        }

        if (!flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            return ['fp' => null, 'reason' => 'locked_by_other'];
        }

        return ['fp' => $fp, 'reason' => null];
    }

    /**
     * Libera lock adquirido via acquire().
     */
    public static function release($fp): void
    {
        if ($fp) {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Detecta o grupo do processo web em runtime.
     *
     * Prioridade:
     * 1. Config manual ('web_process_group') — último recurso
     * 2. Detecção automática via diretório de instalação do WHMCS
     * 3. Fallback 'www-data' com log de warning
     */
    private static function detectWebGroup(): string
    {
        // 1. Configuração manual (último recurso para servidores não-padrão)
        $configured = Database::getConfig('web_process_group', '');
        if ($configured !== '' && function_exists('posix_getgrnam') && posix_getgrnam($configured) !== false) {
            return $configured;
        }

        // 2. Detecção automática via diretório de instalação do WHMCS
        //    (sempre existe, tipicamente de propriedade do processo web)
        $whmcsDir = '/var/www/html/whmcs/';
        if (is_dir($whmcsDir) && function_exists('posix_getgrgid')) {
            $stat = @stat($whmcsDir);
            if ($stat) {
                $groupInfo = posix_getgrgid($stat['gid']);
                if ($groupInfo && !empty($groupInfo['name'])) {
                    return $groupInfo['name'];
                }
            }
        }

        // 3. Fallback: www-data com log de warning
        //    (admin vai ver no dashboard que precisa configurar web_process_group)
        try {
            Database::logEvent('', '', 'lock_config_warning',
                "Não foi possível detectar o grupo do processo web. "
                . "Usando 'www-data' como fallback. Configure 'web_process_group' "
                . "nas configurações do módulo se o lock não funcionar.",
                null);
        } catch (\Throwable $e) {
            // Tabelas podem não existir ainda durante activate()
        }

        return 'www-data';
    }
}
