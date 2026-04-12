<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\LogParser;
use AMS\Fail2Ban\LogViewer;
use AMS\Fail2Ban\Router;
use WHMCS\Database\Capsule;

class LogPathsController
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
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return $this->handlePost();
        }
        return $this->showPage();
    }

    // -----------------------------------------------------------------------
    // AJAX: validate a log path
    // -----------------------------------------------------------------------

    public function handleAjax(string $do, array $post): string
    {
        if ($do === 'validate') {
            $path = $post['path'] ?? $_GET['path'] ?? '';

            if (strpos($path, '..') !== false || !str_starts_with($path, '/')) {
                return json_encode(['success' => false, 'error' => 'Caminho inválido']);
            }

            $parser = new LogParser();
            $result = $parser->validateLogPath($path);
            return json_encode(array_merge(['success' => true], $result));
        }

        return json_encode(['success' => false, 'error' => 'Unknown do']);
    }

    // -----------------------------------------------------------------------
    // POST: add or delete custom log
    // -----------------------------------------------------------------------

    private function handlePost(): string
    {
        $token = $_POST['csrf_token'] ?? '';
        if (!Helper::checkCsrf($token)) {
            Helper::setFlash('danger', 'Token CSRF inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=logpaths');
            return '';
        }

        $do = $_POST['do'] ?? '';

        if ($do === 'add') {
            $label = trim($_POST['label'] ?? '');
            $path  = trim($_POST['path']  ?? '');

            // Sanitizar label: só alfanumérico, hífen, underscore, espaço (max 64)
            $label = preg_replace('/[^a-zA-Z0-9\-_ ]/', '', $label);
            $label = trim(substr($label, 0, 64));

            // Sanitizar path
            $path = preg_replace('/[\x00-\x1F\x7F]/', '', $path);

            if (empty($label)) {
                Helper::setFlash('danger', 'O campo Label é obrigatório.');
            } elseif (empty($path)) {
                Helper::setFlash('danger', 'O campo Path é obrigatório.');
            } elseif (strpos($path, '..') !== false || !str_starts_with($path, '/')) {
                Helper::setFlash('danger', 'Caminho inválido.');
            } else {
                $viewer = new LogViewer();
                if (!$viewer->isValidPath($path)) {
                    Helper::setFlash('danger', 'Caminho fora dos diretórios permitidos (/var/log/).');
                } else {
                    // Normalizar label para chave DB: minúsculas, sem espaços
                    $key = preg_replace('/\s+/', '-', strtolower($label));
                    Database::setConfig("custom_log.{$key}", $path);
                    Helper::setFlash('success', "Log \"{$label}\" adicionado com sucesso.");
                }
            }
        } elseif ($do === 'delete') {
            $key = trim($_POST['key'] ?? '');
            $key = preg_replace('/[^a-zA-Z0-9\-_]/', '', $key);
            if (!empty($key)) {
                Capsule::table('mod_amssoft_fail2ban_config')
                    ->where('key', "custom_log.{$key}")
                    ->delete();
                Helper::setFlash('success', 'Log removido.');
            }
        } else {
            Helper::setFlash('danger', 'Ação desconhecida.');
        }

        Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=logpaths');
        return '';
    }

    // -----------------------------------------------------------------------
    // GET: show page
    // -----------------------------------------------------------------------

    private function showPage(): string
    {
        $parser = new LogParser();

        // Logs auto-descobertos (bem conhecidos que existem no disco)
        $autoLogs = [];
        foreach (LogViewer::WELL_KNOWN_LOGS as $path => $label) {
            if (file_exists($path)) {
                $v = $parser->validateLogPath($path);
                $autoLogs[] = [
                    'label'    => $label,
                    'path'     => $path,
                    'readable' => $v['readable'] ?? false,
                    'size'     => $v['size']     ?? 0,
                ];
            }
        }

        // Logs customizados salvos pelo admin
        $customLogs = [];
        try {
            $rows = Capsule::table('mod_amssoft_fail2ban_config')
                ->where('key', 'like', 'custom_log.%')
                ->orderBy('key')
                ->get();
            foreach ($rows as $row) {
                $dbKey = substr($row->key, strlen('custom_log.'));
                $path  = $row->value ?? '';
                if ($path === '') {
                    continue;
                }
                $v = $parser->validateLogPath($path);
                $customLogs[] = [
                    'key'      => $dbKey,
                    'label'    => $dbKey,
                    'path'     => $path,
                    'readable' => $v['readable'] ?? false,
                    'size'     => $v['size']     ?? 0,
                ];
            }
        } catch (\Throwable $e) {}

        return $this->router->render('logpaths', [
            'auto_logs'   => $autoLogs,
            'custom_logs' => $customLogs,
        ]);
    }
}
