<?php
/**
 * AMS Fail2Ban Manager — WHMCS Addon Module
 * Entry point: prefixed functions required by WHMCS addon API.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;

require_once __DIR__ . '/lib/Router.php';

// ---------------------------------------------------------------------------
// Required WHMCS addon functions
// ---------------------------------------------------------------------------

function amssoft_fail2ban_config(): array
{
    return [
        'name'        => 'AMS SOFT Fail2Ban Manager',
        'description' => 'Gerencia fail2ban diretamente pelo WHMCS — IPs, jails, logs e relatórios.' . '</div>
        <div>Por <a href="https://www.amssoft.com.br/" target="_blank"><strong>AMS SOFT</strong></a></div>',
        'author'      => 'AMS SOFT',
        'authorurl' => 'https://www.amssoft.com.br',
        'language'    => 'portuguese-br',
        'version'     => '2.0.1',
        'fields'      => [
            'sudo_path'       => [
                'FriendlyName' => 'Caminho sudo',
                'Type'         => 'text',
                'Size'         => 50,
                'Default'      => '/usr/bin/sudo',
                'Description'  => 'Caminho completo para o binário sudo',
            ],
            'fail2ban_client' => [
                'FriendlyName' => 'fail2ban-client',
                'Type'         => 'text',
                'Size'         => 50,
                'Default'      => '/usr/bin/fail2ban-client',
                'Description'  => 'Caminho completo para fail2ban-client',
            ],
            'jail_local_path' => [
                'FriendlyName' => 'jail.local',
                'Type'         => 'text',
                'Size'         => 60,
                'Default'      => '/etc/fail2ban/jail.local',
                'Description'  => 'Caminho para o arquivo jail.local',
            ],
            'whmcs_log_path'  => [
                'FriendlyName' => 'Log WHMCS para fail2ban',
                'Type'         => 'text',
                'Size'         => 60,
                'Default'      => '/var/log/whmcs_auth.log',
                'Description'  => 'Arquivo de log de autenticação WHMCS',
            ],
            'enable_hooks'    => [
                'FriendlyName' => 'Habilitar hooks de login',
                'Type'         => 'yesno',
                'Default'      => 'yes',
                'Description'  => 'Registrar falhas de login no log fail2ban',
            ],
            'web_process_group' => [
                'FriendlyName' => 'Grupo do processo web',
                'Type'         => 'text',
                'Size'         => 20,
                'Default'      => '',
                'Description'  => 'Grupo do processo web (ex: www-data, apache). Vazio = detecção automática via diretório do WHMCS.',
            ],
        ],
    ];
}

function amssoft_fail2ban_activate(): array
{
    try {
        if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_logs')) {
            Capsule::schema()->create('mod_amssoft_fail2ban_logs', function ($t) {
                $t->bigIncrements('id');
                $t->string('ip', 45)->index();
                $t->string('jail', 64)->index();
                $t->enum('action', ['ban', 'unban', 'manual_ban', 'manual_unban']);
                $t->string('reason', 255)->nullable();
                $t->timestamp('timestamp')->useCurrent()->index();
                $t->unsignedInteger('admin_id')->nullable();
            });
        }

        if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_config')) {
            Capsule::schema()->create('mod_amssoft_fail2ban_config', function ($t) {
                $t->increments('id');
                $t->string('key', 128)->unique();
                $t->text('value')->nullable();
            });
        }

        if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_ai_suggestions')) {
            Capsule::schema()->create('mod_amssoft_fail2ban_ai_suggestions', function ($t) {
                $t->bigIncrements('id');
                $t->string('ip', 45)->index();
                $t->string('jail', 64)->default('');
                $t->string('threat', 128)->default('');
                $t->enum('severity', ['low', 'medium', 'high', 'critical'])->default('medium');
                $t->unsignedTinyInteger('confidence')->default(0);
                $t->text('evidence')->nullable();
                $t->text('suggested_rule')->nullable();
                $t->text('reason')->nullable();
                $t->unsignedInteger('bantime')->default(3600);
                $t->enum('status', ['pending', 'approved', 'rejected', 'auto_executed'])->default('pending')->index();
                $t->timestamp('created_at')->useCurrent()->index();
                $t->timestamp('resolved_at')->nullable();
                $t->unsignedInteger('resolved_by')->nullable();
                // v3: filtro fail2ban gerado pela IA
                $t->string('filter_name', 64)->nullable();
                $t->text('failregex')->nullable();
                $t->timestamp('filter_created_at')->nullable();
            });
        }

        // Garantir que a jail dedicada ai-bans existe em jail.local
        try {
            $jailConfig = new \AMS\Fail2Ban\JailConfig('/etc/fail2ban/jail.local');
            $existing   = $jailConfig->readJailLocal();
            if (!isset($existing['ai-bans'])) {
                $jailConfig->addJail('ai-bans', [
                    'enabled'  => 'true',
                    'filter'   => 'apache-auth',
                    'logpath'  => '/var/log/apache2/access_whmcs.log',
                    'maxretry' => '5',
                    'findtime' => '600',
                    'bantime'  => '3600',
                    'ignoreip' => '127.0.0.1',
                ]);
            }
        } catch (\Throwable $e) {
            // silencioso — jail será criada automaticamente no primeiro uso
        }

        // Setup do diretório de locks (data/locks/)
        // Lock files precisam ser acessíveis por root (cron) e www-data (painel).
        // O diretório data/ já é www-data:www-data (copiado do repo).
        // Quando root criar lock files aqui, o setgid herda o grupo.
        $dataDir  = __DIR__ . '/data/';
        $locksDir = $dataDir . 'locks/';
        if (!is_dir($locksDir)) {
            @mkdir($locksDir, 0770, true);
        }
        @chmod($locksDir, 2770); // setgid: lock files herdam grupo do diretório

        // .htaccess para bloquear acesso HTTP ao diretório data/
        $htaccess = $dataDir . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
        }

        return ['status' => 'success', 'description' => 'AMS Fail2Ban Manager instalado com sucesso.'];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => $e->getMessage()];
    }
}

function amssoft_fail2ban_deactivate(): array
{
    try {
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_logs');
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_config');
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_ai_suggestions');
        Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_geo_cache');
        return ['status' => 'success', 'description' => 'AMS Fail2Ban Manager removido.'];
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => $e->getMessage()];
    }
}

/**
 * Migração automática v2: cria a tabela de sugestões da IA se ainda não existir.
 * Chamada em todo carregamento do módulo para garantir compatibilidade com
 * instalações que ativaram o módulo antes da atualização para v2.
 */
function amssoft_fail2ban_migrate_v2(): void
{
    if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_ai_suggestions')) {
        Capsule::schema()->create('mod_amssoft_fail2ban_ai_suggestions', function ($t) {
            $t->bigIncrements('id');
            $t->string('ip', 45)->index();
            $t->string('jail', 64)->default('');
            $t->string('threat', 128)->default('');
            $t->enum('severity', ['low', 'medium', 'high', 'critical'])->default('medium');
            $t->unsignedTinyInteger('confidence')->default(0);
            $t->text('evidence')->nullable();
            $t->text('suggested_rule')->nullable();
            $t->text('reason')->nullable();
            $t->unsignedInteger('bantime')->default(3600);
            $t->enum('status', ['pending', 'approved', 'rejected', 'auto_executed'])->default('pending')->index();
            $t->timestamp('created_at')->useCurrent()->index();
            $t->timestamp('resolved_at')->nullable();
            $t->unsignedInteger('resolved_by')->nullable();
        });
    }
}

/**
 * Migração automática v4: multi-provider IA.
 * - Migra chaves antigas (ai_api_key, ai_model) para formato por provedor
 * - Garante que ai_active_provider exista
 * - Limpa base URLs de provedores que não precisam de URL editável
 * Idempotente: só executa se as chaves antigas existirem E as novas estiverem vazias.
 */
function amssoft_fail2ban_migrate_v4(): void
{
    // Migrar ai_api_key → ai_provider_anthropic_api_key (preserva valor criptografado)
    $oldKey = \AMS\Fail2Ban\Database::getConfig('ai_api_key', '');
    if ($oldKey !== '' && \AMS\Fail2Ban\Database::getConfig('ai_provider_anthropic_api_key', '') === '') {
        \AMS\Fail2Ban\Database::setConfig('ai_provider_anthropic_api_key', $oldKey);
    }

    // Migrar ai_model → ai_provider_anthropic_model
    $oldModel = \AMS\Fail2Ban\Database::getConfig('ai_model', '');
    if ($oldModel !== '' && \AMS\Fail2Ban\Database::getConfig('ai_provider_anthropic_model', '') === '') {
        \AMS\Fail2Ban\Database::setConfig('ai_provider_anthropic_model', $oldModel);
    }

    // Garantir que ai_active_provider existe (default: anthropic)
    if (\AMS\Fail2Ban\Database::getConfig('ai_active_provider', '') === '') {
        \AMS\Fail2Ban\Database::setConfig('ai_active_provider', 'anthropic');
    }

    // Limpar base URL salva para provedores que não precisam de URL editável
    foreach (\AMS\Fail2Ban\AIAnalyzer::getProviders() as $key => $def) {
        if (!$def['needs_base_url']) {
            $saved = \AMS\Fail2Ban\Database::getConfig("ai_provider_{$key}_base_url", '');
            if ($saved !== '') {
                \AMS\Fail2Ban\Database::setConfig("ai_provider_{$key}_base_url", '');
            }
        }
    }
}

/**
 * Migração automática v3: adiciona colunas de filtro fail2ban à tabela de sugestões.
 * Idempotente: usa hasColumn() para verificar antes de adicionar.
 */
function amssoft_fail2ban_migrate_v3(): void
{
    if (!Capsule::schema()->hasTable('mod_amssoft_fail2ban_ai_suggestions')) {
        return;
    }
    Capsule::schema()->table('mod_amssoft_fail2ban_ai_suggestions', function ($t) {
        if (!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions', 'filter_name')) {
            $t->string('filter_name', 64)->nullable()->after('resolved_by');
        }
        if (!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions', 'failregex')) {
            $t->text('failregex')->nullable()->after('filter_name');
        }
        if (!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_ai_suggestions', 'filter_created_at')) {
            $t->timestamp('filter_created_at')->nullable()->after('failregex');
        }
    });
}

/**
 * Migração automática v5: tabela de cache GeoIP.
 * Idempotente: usa hasTable() para verificar antes de criar.
 */
function amssoft_fail2ban_migrate_v5(): void
{
    if (Capsule::schema()->hasTable('mod_amssoft_fail2ban_geo_cache')) {
        return;
    }
    Capsule::schema()->create('mod_amssoft_fail2ban_geo_cache', function ($t) {
        $t->string('ip', 45)->primary();
        $t->string('country', 64)->nullable();
        $t->string('country_code', 2)->nullable();
        $t->string('region', 128)->nullable();
        $t->string('isp', 255)->nullable();
        $t->string('asn', 32)->nullable();
        $t->timestamp('updated_at')->useCurrent();
        $t->index('updated_at', 'idx_updated');
    });
}

/**
 * Migração automática v6: limpa chave de protocolo do MiMo.
 * O protocolo foi fixado em 'openai' no registry — a chave no banco é lixo.
 * Idempotente: só limpa se a chave existir.
 */
function amssoft_fail2ban_migrate_v6(): void
{
    $protocol = \AMS\Fail2Ban\Database::getConfig('ai_provider_mimo_protocol', '');
    if ($protocol !== '') {
        \AMS\Fail2Ban\Database::setConfig('ai_provider_mimo_protocol', '');
    }
}

/**
 * v7: Expandir ENUM da coluna action para incluir eventos de auto-criação
 * e concorrência (analysis_locked). Idempotente — ALTER TABLE só executa
 * se o ENUM ainda não tiver os novos valores.
 */
function amssoft_fail2ban_migrate_v7(): void
{
    try {
        \WHMCS\Database\Capsule::statement("
            ALTER TABLE mod_amssoft_fail2ban_logs
            MODIFY action ENUM(
                'ban','unban','manual_ban','manual_unban',
                'jail_created','auto_filter_fallback','auto_filter_error',
                'auto_filter_dedup','auto_filter_orphan','auto_filter_orphan_cleanup_failed',
                'analysis_locked'
            ) NOT NULL
        ");
    } catch (\Throwable $e) {
        // Silencioso — se a tabela não existe, activate() cria com o ENUM correto
    }
}

/**
 * v8: Lock directory no projeto + ENUM lock_config_warning.
 *
 * Resolve bug onde lock files criados por root (644) em /tmp não podiam ser
 * abertos por www-data, causando falso "analysis_locked" em toda análise via painel.
 *
 * - Adiciona 'lock_config_warning' ao ENUM da coluna action
 * - Garante data/locks/ com permissão 2770 (setgid)
 * - Garante data/.htaccess com Deny from all
 */
function amssoft_fail2ban_migrate_v8(): void
{
    // 1. Expandir ENUM
    try {
        \WHMCS\Database\Capsule::statement("
            ALTER TABLE mod_amssoft_fail2ban_logs
            MODIFY action ENUM(
                'ban','unban','manual_ban','manual_unban',
                'jail_created','auto_filter_fallback','auto_filter_error',
                'auto_filter_dedup','auto_filter_orphan','auto_filter_orphan_cleanup_failed',
                'analysis_locked','lock_config_warning'
            ) NOT NULL DEFAULT 'ban'
        ");
    } catch (\Throwable $e) {
        // Silencioso — se a tabela não existe, activate() cria com o ENUM correto
    }

    // 2. Garantir data/locks/ existe com setgid (para instalações existentes)
    $locksDir = dirname(__DIR__) . '/data/locks/';
    if (!is_dir($locksDir)) {
        @mkdir($locksDir, 0770, true);
    }
    @chmod($locksDir, 2770); // setgid: lock files herdam grupo

    // Verificar se o grupo do diretório permite cross-user locking.
    // Se grupo=root: setgid herda root → lock files ficam root:root 660
    // → www-data não consegue fopen → falso "analysis_locked" (bug original).
    // Grupo=www-data (ou qualquer não-root): setgid herda → root:www-data 660 → OK.
    $stat = @stat($locksDir);
    if ($stat && function_exists('posix_getgrgid')) {
        $groupInfo = posix_getgrgid($stat['gid']);
        $currentGroup = $groupInfo['name'] ?? (string)$stat['gid'];
        if ($currentGroup === 'root') {
            // Grupo=root: www-data não vai conseguir criar/abrir lock files.
            // Logar warning visível no dashboard.
            try {
                \AMS\Fail2Ban\Database::logEvent('', '', 'lock_config_warning',
                    "Diretório data/locks/ tem grupo 'root'. Lock cross-user (cron→painel) não funciona. "
                    . "Corrija: chgrp www-data " . $locksDir . " && chmod 2770 " . $locksDir,
                    null);
            } catch (\Throwable $e) {}
        }
    }
    // NOTA: NÃO é necessário chown root:www-data. O diretório pode ser
    // www-data:www-data 2770. Root ignora permissões de diretório no Linux
    // e setgid faz lock files herdam grupo www-data. Testado em produção.

    // 3. Garantir data/.htaccess existe
    $htaccess = dirname(__DIR__) . '/data/.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
    }
}

/**
 * v9: Adiciona coluna source_log na tabela de sugestões.
 *
 * Propaga o path do log de origem de cada sugestão — elimina a necessidade
 * de inferir logpath por keywords no failregex (causa raiz do bug onde
 * filtros auto-criados apontavam para whmcs_auth.log com failregex Apache).
 *
 * Idempotente — ADD COLUMN só executa se a coluna não existir.
 */
function amssoft_fail2ban_migrate_v9(): void
{
    try {
        \WHMCS\Database\Capsule::statement(
            "ALTER TABLE mod_amssoft_fail2ban_ai_suggestions
             ADD COLUMN source_log VARCHAR(500) DEFAULT NULL AFTER failregex"
        );
    } catch (\Throwable $e) {
        // Coluna já existe — idempotente
    }
}

/**
 * v10: Expandir ENUM com 'already_banned'.
 *
 * Quando executeBan() falha mas o IP já está banido (de ciclo anterior),
 * processSuggestion() mantém auto_executed e registra already_banned
 * em vez de reverter para pending (que causaria loop infinito).
 */
function amssoft_fail2ban_migrate_v10(): void
{
    try {
        \WHMCS\Database\Capsule::statement("
            ALTER TABLE mod_amssoft_fail2ban_logs
            MODIFY action ENUM(
                'ban','unban','manual_ban','manual_unban',
                'jail_created','auto_filter_fallback','auto_filter_error',
                'auto_filter_dedup','auto_filter_orphan','auto_filter_orphan_cleanup_failed',
                'analysis_locked','lock_config_warning','already_banned'
            ) NOT NULL DEFAULT 'ban'
        ");
    } catch (\Throwable $e) {
        // Silencioso
    }
}

/**
 * v11: Corrigir jail ai-bans sem logpath e/ou ignoreip (bug desde v1.0.0).
 *
 * A jail ai-bans era criada sem o campo logpath (obrigatório no fail2ban).
 * O campo ignoreip também podia se perder em round-trips de saveJail()
 * porque não estava na whitelist de campos permitidos.
 *
 * Idempotente: só altera se ai-bans existir E algum campo estiver faltando.
 */
function amssoft_fail2ban_migrate_v11(): void
{
    try {
        $jailConfig = new \AMS\Fail2Ban\JailConfig('/etc/fail2ban/jail.local');
        $existing   = $jailConfig->readJailLocal();

        if (isset($existing['ai-bans'])) {
            $fix = [];
            if (empty($existing['ai-bans']['logpath'])) {
                $fix['logpath'] = '/var/log/apache2/access_whmcs.log';
            }
            if (empty($existing['ai-bans']['ignoreip'])) {
                $fix['ignoreip'] = '127.0.0.1';
            }
            if (!empty($fix)) {
                $jailConfig->saveJail('ai-bans', $fix);
            }
        }
    } catch (\Throwable $e) {
        // Silencioso — jail.local pode não existir ainda
    }
}

function amssoft_fail2ban_output(array $vars): void
{
    // Migração automática: garante que tabelas do v2 existam mesmo em instalações antigas
    try {
        amssoft_fail2ban_migrate_v2();
    } catch (\Exception $e) {
        // Silencioso — não interrompe o carregamento do módulo
    }

    // Migração automática v3: colunas de filtro fail2ban
    try {
        amssoft_fail2ban_migrate_v3();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v4: multi-provider IA
    try {
        amssoft_fail2ban_migrate_v4();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v5: tabela de cache GeoIP
    try {
        amssoft_fail2ban_migrate_v5();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v6: limpar chave de protocolo do MiMo
    try {
        amssoft_fail2ban_migrate_v6();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v7: expandir ENUM da coluna action
    try {
        amssoft_fail2ban_migrate_v7();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v8: diretório de lock compartilhado + ENUM lock_config_warning
    try {
        amssoft_fail2ban_migrate_v8();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v9: coluna source_log na tabela de sugestões
    try {
        amssoft_fail2ban_migrate_v9();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v10: ENUM already_banned
    try {
        amssoft_fail2ban_migrate_v10();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Migração automática v11: ai-bans sem logpath (bug desde v1.0.0)
    try {
        amssoft_fail2ban_migrate_v11();
    } catch (\Exception $e) {
        // Silencioso
    }

    // Detect AJAX requests — clear any WHMCS output buffers, return JSON and exit.
    $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

    if ($isAjax) {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        $router = new \AMS\Fail2Ban\Router($vars);
        echo $router->handleAjax(
            $_GET['action'] ?? '',
            $_GET['do']     ?? '',
            $_POST          ?? []
        );
        exit;
    }

    $router = new \AMS\Fail2Ban\Router($vars);
    echo $router->dispatch($_GET['action'] ?? 'dashboard');
}

function amssoft_fail2ban_sidebar(array $vars): string
{
    $ml = htmlspecialchars($vars['modulelink'] ?? '', ENT_QUOTES, 'UTF-8');
    return '<ul class="list-unstyled" style="line-height:2">
        <li><a href="' . $ml . '&amp;action=dashboard">&#127759; Dashboard</a></li>
        <li><a href="' . $ml . '&amp;action=ips">&#128683; IPs Banidos</a></li>
        <li><a href="' . $ml . '&amp;action=jails">&#128274; Jails</a></li>
        <li><a href="' . $ml . '&amp;action=logpaths">&#128196; Log Paths</a></li>
        <li><a href="' . $ml . '&amp;action=reports">&#128202; Relatórios</a></li>
        <li><a href="' . $ml . '&amp;action=logviewer">&#128220; Log Viewer</a></li>
        <li><a href="' . $ml . '&amp;action=ai">&#129302; IA / Sugestões</a></li>
    </ul>';
}
