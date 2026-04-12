<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\Database;
use AMS\Fail2Ban\Helper;
use AMS\Fail2Ban\LogParser;
use AMS\Fail2Ban\Router;

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

            // Reject path traversal / non-absolute
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
    // POST: save logpaths
    // -----------------------------------------------------------------------

    private function handlePost(): string
    {
        $token = $_POST['csrf_token'] ?? '';
        if (!Helper::checkCsrf($token)) {
            Helper::setFlash('danger', 'Token CSRF inválido.');
            Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=logpaths');
        }

        $paths  = $_POST['logpath'] ?? [];    // array: jail => path
        $config = $this->router->makeJailConfig();
        $saved  = 0;

        foreach ($paths as $jail => $path) {
            $jail = Helper::sanitizeJail($jail);
            $path = trim((string)$path);

            if (!$jail) {
                continue;
            }

            // [SEC-2] Strip control characters (newlines, null bytes) before path checks
            // to prevent INI injection via embedded \n in the logpath value.
            $path = preg_replace('/[\x00-\x1F\x7F]/', '', $path);

            // Validate path
            if ($path !== '' && (strpos($path, '..') !== false || !str_starts_with($path, '/'))) {
                continue; // reject unsafe paths silently
            }

            // Persist to DB config store
            Database::setConfig("logpath.{$jail}", $path);

            // Also update jail.local if the path is non-empty
            if ($path !== '') {
                $config->saveJail($jail, ['logpath' => $path]);
            }

            $saved++;
        }

        Helper::setFlash('success', "Log paths salvos ({$saved} jail(s) atualizados).");
        Helper::redirect(($this->vars['modulelink'] ?? '') . '&action=logpaths');
        return '';
    }

    // -----------------------------------------------------------------------
    // GET: show page
    // -----------------------------------------------------------------------

    private function showPage(): string
    {
        $jailConfig = $this->router->makeJailConfig();
        $jailData   = [];

        try {
            $rawData  = $jailConfig->readJailLocal();
            // Remove DEFAULT e stubs de desabilitação do sistema (ex: [sshd] enabled=false)
            unset($rawData['DEFAULT']);
            foreach ($rawData as $jailName => $cfg) {
                $keys = array_keys($cfg);
                if ($keys === ['enabled'] && strtolower($cfg['enabled']) === 'false') {
                    unset($rawData[$jailName]);
                }
            }
            $jailData = $rawData;
        } catch (\Throwable $e) {
            // jail.local might not be accessible
        }

        // Merge saved DB overrides
        $parser    = new LogParser();
        $jailPaths = [];

        foreach (array_keys($jailData) as $jail) {
            $dbPath  = Database::getConfig("logpath.{$jail}");
            $iniPath = $jailData[$jail]['logpath'] ?? '';
            $path    = $dbPath ?? $iniPath;

            $validation = ($path !== '') ? $parser->validateLogPath($path) : null;

            $jailPaths[$jail] = [
                'path'       => $path,
                'validation' => $validation,
            ];
        }

        return $this->router->render('logpaths', [
            'jail_paths' => $jailPaths,
        ]);
    }
}
