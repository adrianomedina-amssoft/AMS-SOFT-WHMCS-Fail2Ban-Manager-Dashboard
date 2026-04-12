<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\Router;

class JailsController
{
    private array  $vars;
    private Router $router;

    public function __construct(array $vars, Router $router)
    {
        $this->vars   = $vars;
        $this->router = $router;
    }

    public function handle(string $action): string
    {
        if ($action === 'jail_edit') {
            return $this->editJailPage();
        }

        // POST on jails list (non-AJAX toggle)
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return $this->handlePost();
        }

        return $this->listJails();
    }

    // -----------------------------------------------------------------------
    // AJAX handler (toggle enable/disable)
    // -----------------------------------------------------------------------

    public function handleAjax(string $do, array $post): string
    {
        // Reload geral não precisa de jail específico
        if ($do === 'reload_all') {
            $config   = $this->router->makeJailConfig();
            $reloaded = $config->reloadAll();
            return json_encode(['success' => $reloaded]);
        }

        $jail = Helper::sanitizeJail($post['jail'] ?? '');
        if (!$jail) {
            return json_encode(['success' => false, 'error' => 'Jail inválido']);
        }

        $config = $this->router->makeJailConfig();

        if ($do === 'enable') {
            $ok = $config->enableJail($jail);
            if ($ok) {
                $config->reloadJail($jail);
            }
            return json_encode(['success' => $ok]);
        }

        if ($do === 'disable') {
            $ok = $config->disableJail($jail);
            if ($ok) {
                $config->reloadJail($jail);
            }
            return json_encode(['success' => $ok]);
        }

        if ($do === 'remove') {
            $warning = null;
            $ok = $config->removeJail($jail);
            if ($ok) {
                $reloaded = $config->reloadAll();
                Database::logEvent('-', $jail, 'manual_ban', 'Jail removido via WHMCS', Helper::adminId());
                if (!$reloaded) {
                    $output  = trim($config->getLastReloadOutput());
                    $warning = 'Jail removido do jail.local, mas o fail2ban não pôde ser recarregado.';
                    if ($output !== '') {
                        $warning .= "\n\nSaída:\n" . $output;
                    }
                }
                return json_encode([
                    'success' => true,
                    'warning' => $reloaded ? null : $warning,
                ]);
            }
            return json_encode(['success' => false, 'error' => "Não foi possível remover '{$jail}'. Verifique permissões em jail.local."]);
        }

        return json_encode(['success' => false, 'error' => 'Unknown do']);
    }

    // -----------------------------------------------------------------------
    // POST handler (non-AJAX fallback for jail list toggle + jail_edit save)
    // -----------------------------------------------------------------------

    private function handlePost(): string
    {
        $token = $_POST['csrf_token'] ?? '';
        if (!Helper::checkCsrf($token)) {
            Helper::setFlash('danger', 'Token CSRF inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        }

        $do     = $_POST['do'] ?? '';
        $config = $this->router->makeJailConfig();

        // Add new jail — jail name comes from new_jail, not jail
        if ($do === 'add') {
            return $this->addJailFromPost($config);
        }

        $jail = Helper::sanitizeJail($_POST['jail'] ?? '');

        if (!$jail) {
            Helper::setFlash('danger', 'Jail inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        }

        if ($do === 'enable') {
            $ok = $config->enableJail($jail);
            if ($ok) {
                $config->reloadJail($jail);
                Database::logEvent('-', $jail, 'manual_unban', 'Jail habilitado via WHMCS', Helper::adminId());
                Helper::setFlash('success', "Jail {$jail} habilitado.");
            } else {
                Helper::setFlash('danger', "Erro ao habilitar jail {$jail}.");
            }
        } elseif ($do === 'disable') {
            $ok = $config->disableJail($jail);
            if ($ok) {
                $config->reloadJail($jail);
                Database::logEvent('-', $jail, 'manual_ban', 'Jail desabilitado via WHMCS', Helper::adminId());
                Helper::setFlash('success', "Jail {$jail} desabilitado.");
            } else {
                Helper::setFlash('danger', "Erro ao desabilitar jail {$jail}.");
            }
        } elseif ($do === 'remove') {
            $ok = $config->removeJail($jail);
            if ($ok) {
                $reloaded = $config->reloadAll();
                Database::logEvent('-', $jail, 'manual_ban', 'Jail removido via WHMCS', Helper::adminId());
                if ($reloaded) {
                    Helper::setFlash('success', "Jail {$jail} removido e fail2ban recarregado.");
                } else {
                    $output = trim($config->getLastReloadOutput());
                    Helper::setFlash(
                        'warning',
                        "Jail {$jail} removido, mas o fail2ban não pôde ser recarregado automaticamente.",
                        $output !== '' ? $output : ''
                    );
                }
            } else {
                Helper::setFlash('danger', "Erro ao remover jail {$jail}.");
            }
        } elseif ($do === 'save') {
            return $this->saveJail($jail, $config);
        }

        Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        return ''; // unreachable
    }

    private function addJailFromPost(\AMS\Fail2Ban\JailConfig $config): string
    {
        $jail = Helper::sanitizeJail($_POST['new_jail'] ?? '');
        if (!$jail) {
            Helper::setFlash('danger', 'Nome do jail inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        }

        $maxretry = max(1, min(100,   (int)($_POST['maxretry'] ?? 5)));
        $findtime = max(60, min(86400, (int)($_POST['findtime'] ?? 600)));
        $bantime  = (int)($_POST['bantime'] ?? 3600);
        if ($bantime !== -1) {
            $bantime = max(60, min(2592000, $bantime));
        }

        $logpath = trim($_POST['logpath'] ?? '');
        $logpath = preg_replace('/[\x00-\x1F\x7F]/', '', $logpath);
        if ($logpath !== '' && (strpos($logpath, '..') !== false || !str_starts_with($logpath, '/'))) {
            $logpath = '';
        }

        $filter  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['filter'] ?? '');
        $enabled = isset($_POST['enabled']) ? 'true' : 'false';

        // Pre-flight: valida que o filtro que vai ser usado realmente existe em filter.d.
        // Sem filtro explícito, fail2ban usa filter.d/{jail}.conf (implied pelo nome da jail).
        $filterDir = '/etc/fail2ban/filter.d/';
        if ($filter === '') {
            $impliedFilter = $filterDir . $jail . '.conf';
            if (!file_exists($impliedFilter)) {
                Helper::setFlash(
                    'danger',
                    "Nenhum filtro selecionado para o jail '{$jail}'. O fail2ban procuraria por {$impliedFilter}, mas esse arquivo não existe. Selecione um filtro da lista ou crie o arquivo de filtro antes de criar a jail."
                );
                Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
            }
        } else {
            $explicitFilter = $filterDir . $filter . '.conf';
            if (!file_exists($explicitFilter)) {
                Helper::setFlash(
                    'danger',
                    "Filtro '{$filter}' não encontrado em {$filterDir}. Selecione um filtro válido da lista."
                );
                Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
            }
        }

        $params = [
            'enabled'  => $enabled,
            'maxretry' => (string)$maxretry,
            'findtime' => (string)$findtime,
            'bantime'  => (string)$bantime,
        ];
        if ($filter !== '') {
            $params['filter'] = $filter;
        }
        if ($logpath !== '') {
            $params['logpath'] = $logpath;
        }

        $ok = $config->addJail($jail, $params);
        if ($ok) {
            $reloaded = $config->reloadAll();
            Database::logEvent('-', $jail, 'manual_ban', 'Jail criado via WHMCS', Helper::adminId());
            if ($reloaded) {
                Helper::setFlash('success', "Jail {$jail} criado e fail2ban recarregado.");
            } else {
                $output  = trim($config->getLastReloadOutput());
                $message = "Jail {$jail} criado em jail.local, mas o fail2ban não pôde ser recarregado.";

                // Detecta jails pré-existentes com logpath ausente (causa o reload falhar)
                if (preg_match_all('/Have not found any log file for (\S+) jail/i', $output, $m)) {
                    $broken = array_diff(array_unique($m[1]), [$jail]);
                    if (!empty($broken)) {
                        $message .= ' Jails sem logpath: ' . implode(', ', $broken) . '. Edite-as e adicione um logpath ou remova-as.';
                    }
                }
                // Detecta jails pré-existentes com filtro ausente (puladas, mas geram erros)
                if (preg_match_all("/Errors in jail '([^']+)'\. Skipping/i", $output, $m2)) {
                    $noFilter = array_diff(array_unique($m2[1]), [$jail]);
                    if (!empty($noFilter)) {
                        $message .= ' Jails sem filtro válido: ' . implode(', ', $noFilter) . '. Edite-as e selecione um filtro ou remova-as.';
                    }
                }

                Helper::setFlash('warning', $message, $output !== '' ? $output : '');
            }
        } else {
            $permErr = $config->checkPermissions();
            if ($permErr !== null) {
                Helper::setFlash('danger', $permErr);
            } else {
                Helper::setFlash('danger', "Erro ao criar jail {$jail}. Verifique se já existe.");
            }
        }

        Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        return '';
    }

    // -----------------------------------------------------------------------
    // Jail edit page
    // -----------------------------------------------------------------------

    private function editJailPage(): string
    {
        // Save on POST
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['csrf_token'] ?? '';
            if (!Helper::checkCsrf($token)) {
                Helper::setFlash('danger', 'Token CSRF inválido.');
                Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
            }
            $jail   = Helper::sanitizeJail($_POST['jail'] ?? $_GET['jail'] ?? '');
            $config = $this->router->makeJailConfig();
            return $this->saveJail($jail, $config);
        }

        $jail   = Helper::sanitizeJail($_GET['jail'] ?? '');
        $config = $this->router->makeJailConfig();
        $data   = $config->readJailLocal();

        if (!$jail || !isset($data[$jail])) {
            Helper::setFlash('danger', 'Jail não encontrado.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        }

        return $this->router->render('jail_edit', [
            'jail'       => $jail,
            'jail_data'  => $data[$jail],
        ]);
    }

    private function saveJail(string $jail, \AMS\Fail2Ban\JailConfig $config): string
    {
        if (!$jail) {
            Helper::setFlash('danger', 'Jail inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        }

        // Validate and sanitise numeric fields
        $maxretry = max(1, min(100,  (int)($_POST['maxretry'] ?? 5)));
        $findtime = max(60, min(86400, (int)($_POST['findtime'] ?? 600)));
        $bantime  = (int)($_POST['bantime'] ?? 3600);
        if ($bantime !== -1) {
            $bantime = max(60, min(2592000, $bantime));
        }

        // logpath: validate no path traversal
        $logpath = trim($_POST['logpath'] ?? '');
        // [SEC-2] Strip control characters (newlines, null bytes) before path checks
        // to prevent INI injection via embedded \n in the logpath value.
        $logpath = preg_replace('/[\x00-\x1F\x7F]/', '', $logpath);
        if ($logpath !== '' && (strpos($logpath, '..') !== false || !str_starts_with($logpath, '/'))) {
            $logpath = ''; // reject unsafe path
        }

        $enabled = isset($_POST['enabled']) ? 'true' : 'false';

        $params = [
            'maxretry' => (string)$maxretry,
            'findtime' => (string)$findtime,
            'bantime'  => (string)$bantime,
            'enabled'  => $enabled,
        ];
        if ($logpath !== '') {
            $params['logpath'] = $logpath;
        }

        $ok = $config->saveJail($jail, $params);
        if ($ok) {
            $config->reloadJail($jail);
            $reason = "Config atualizada: maxretry={$maxretry} findtime={$findtime} bantime={$bantime} enabled={$enabled}";
            Database::logEvent('-', $jail, 'manual_ban', $reason, Helper::adminId());
            Helper::setFlash('success', "Jail {$jail} salvo e recarregado.");
        } else {
            Helper::setFlash('danger', "Erro ao salvar jail {$jail}.");
        }

        Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=jails');
        return ''; // unreachable
    }

    // -----------------------------------------------------------------------
    // List jails
    // -----------------------------------------------------------------------

    private function listJails(): string
    {
        $config     = $this->router->makeJailConfig();
        $client     = $this->router->makeClient();
        $jailData   = [];
        $liveStatus = [];
        $error      = null;

        try {
            $jailData = $config->readJailLocal();
        } catch (\Throwable $e) {
            $error = 'Erro ao ler jail.local: ' . $e->getMessage();
        }

        try {
            if ($client->ping()) {
                foreach (array_keys($jailData) as $j) {
                    if ($j === 'DEFAULT') {
                        continue;
                    }
                    $liveStatus[$j] = $client->getJailStatus($j);
                }
            }
        } catch (\Throwable $e) {
            // fail2ban offline — proceed with config-only view
        }

        // Remove [DEFAULT] e stubs de desabilitação do sistema (ex: [sshd] enabled=false)
        // Stubs: seção com apenas a chave "enabled" definida como "false" — são overrides
        // internos para evitar erros de reload do fail2ban, não jails gerenciáveis pelo usuário.
        unset($jailData['DEFAULT']);
        foreach ($jailData as $jailName => $cfg) {
            $keys = array_keys($cfg);
            if ($keys === ['enabled'] && strtolower($cfg['enabled']) === 'false') {
                unset($jailData[$jailName]);
            }
        }

        // Collect available filters from filter.d for the "Novo Jail" modal
        $availableFilters = [];
        $filterDir = '/etc/fail2ban/filter.d';
        if (is_dir($filterDir)) {
            foreach (glob($filterDir . '/*.conf') ?: [] as $f) {
                $availableFilters[] = basename($f, '.conf');
            }
            sort($availableFilters);
        }

        // Parâmetros para pré-preencher e abrir o modal "Novo Jail" automaticamente
        // (usado quando o admin vem da tela de Sugestões IA com jail inexistente).
        $prefillJail    = Helper::sanitizeJail($_GET['new_jail'] ?? '');
        $prefillFilter  = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['filter'] ?? '');
        $prefillLogpath = trim($_GET['logpath'] ?? '');
        $prefillLogpath = preg_replace('/[\x00-\x1F\x7F]/', '', $prefillLogpath);
        if ($prefillLogpath !== '' && (str_contains($prefillLogpath, '..') || !str_starts_with($prefillLogpath, '/'))) {
            $prefillLogpath = '';
        }
        $prefillMaxretry = max(1,  min(100,    (int)($_GET['maxretry'] ?? 5)));
        $prefillFindtime = max(60, min(86400,   (int)($_GET['findtime'] ?? 600)));
        $prefillBantime  = (int)($_GET['bantime'] ?? 3600);
        if ($prefillBantime !== -1) {
            $prefillBantime = max(60, min(2592000, $prefillBantime));
        }
        $openAddModal   = !empty($_GET['open_modal']) && !empty($prefillJail);

        return $this->router->render('jails', [
            'jail_data'          => $jailData,
            'live_status'        => $liveStatus,
            'error'              => $error,
            'available_filters'  => $availableFilters,
            'prefill_jail'       => $prefillJail,
            'prefill_filter'     => $prefillFilter,
            'prefill_logpath'    => $prefillLogpath,
            'prefill_maxretry'   => $prefillMaxretry,
            'prefill_findtime'   => $prefillFindtime,
            'prefill_bantime'    => $prefillBantime,
            'open_add_modal'     => $openAddModal,
        ]);
    }
}
