<?php
namespace AMS\Fail2Ban;

// ---------------------------------------------------------------------------
// Namespace autoloader — maps AMS\Fail2Ban\* → lib/ and controllers/
// ---------------------------------------------------------------------------
(static function (): void {
    static $registered = false;
    if ($registered) {
        return;
    }
    $registered = true;

    $libDir         = __DIR__ . '/';
    $controllersDir = __DIR__ . '/../controllers/';

    spl_autoload_register(function (string $class) use ($libDir, $controllersDir): void {
        $prefixes = [
            'AMS\\Fail2Ban\\Controllers\\' => $controllersDir,
            'AMS\\Fail2Ban\\'              => $libDir,
        ];
        foreach ($prefixes as $prefix => $dir) {
            if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
                continue;
            }
            $relative = substr($class, strlen($prefix));
            $file     = $dir . str_replace('\\', '/', $relative) . '.php';
            if (file_exists($file)) {
                require_once $file;
            }
            return;
        }
    });
})();

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
class Router
{
    private array $vars;

    /** Maps action name → controller FQCN */
    private const CONTROLLER_MAP = [
        'dashboard'   => Controllers\DashboardController::class,
        'ips'         => Controllers\IpsController::class,
        'jails'       => Controllers\JailsController::class,
        'jail_edit'   => Controllers\JailsController::class,
        'logpaths'    => Controllers\LogPathsController::class,
        'reports'     => Controllers\ReportsController::class,
        'logviewer'   => Controllers\LogViewerController::class,
        'ai'          => Controllers\AIController::class,
        'ai_settings' => Controllers\AIController::class,
    ];

    public function __construct(array $vars)
    {
        $this->vars = $vars;
    }

    // -----------------------------------------------------------------------
    // Dispatch — regular page request
    // -----------------------------------------------------------------------

    public function dispatch(string $action): string
    {
        Helper::requireAdmin();

        $controllerClass = self::CONTROLLER_MAP[$action] ?? Controllers\DashboardController::class;
        $controller      = new $controllerClass($this->vars, $this);
        return $controller->handle($action);
    }

    // -----------------------------------------------------------------------
    // Dispatch — AJAX request (called from amssoft_fail2ban_output when XHR)
    // -----------------------------------------------------------------------

    public function handleAjax(string $action, string $do, array $post): string
    {
        if (Helper::adminId() <= 0) {
            return json_encode(['success' => false, 'error' => 'Unauthorized']);
        }

        // [SEC-12] CSRF validado incondicionalmente para toda requisição AJAX POST.
        // A verificação condicional anterior permitia bypass com body vazio
        // (Content-Length: 0) para ações não listadas como run_now e ping_api.
        $token = $post['csrf_token'] ?? '';
        if (!Helper::checkCsrf($token)) {
            return json_encode(['success' => false, 'error' => 'Invalid CSRF token']);
        }

        $controllerClass = self::CONTROLLER_MAP[$action] ?? null;
        if ($controllerClass === null) {
            return json_encode(['success' => false, 'error' => 'Unknown action']);
        }

        $controller = new $controllerClass($this->vars, $this);
        if (!method_exists($controller, 'handleAjax')) {
            return json_encode(['success' => false, 'error' => 'Action not AJAX-capable']);
        }

        $result = $controller->handleAjax($do, $post);

        // [SEC-7] Inject the (possibly rotated) CSRF token into every JSON response so
        // the JS helper (window.AMSFB.csrfToken) stays in sync after token rotation.
        $decoded = json_decode($result, true);
        if (is_array($decoded)) {
            $decoded['csrf_token'] = Helper::csrfToken();
            return json_encode($decoded);
        }
        return $result;
    }

    // -----------------------------------------------------------------------
    // Template rendering
    // -----------------------------------------------------------------------

    /**
     * Renders $template (file in templates/) with $data, wrapping in layout.tpl.
     * Returns the final HTML string.
     */
    public function render(string $template, array $data): string
    {
        $shared = [
            'vars'           => $this->vars,
            'modulelink'     => $this->vars['modulelink'] ?? '',
            'current_action' => $_GET['action'] ?? 'dashboard',
            'csrf_token'     => Helper::csrfToken(),
            'flash'          => Helper::getFlash(),
            'asset_base'     => Helper::assetBase(),
            'e'              => fn ($v) => Helper::e($v),
        ];

        $data   = array_merge($shared, $data);
        $content = $this->renderFile($template . '.tpl', $data);

        $data['content'] = $content;
        return $this->renderFile('layout.tpl', $data);
    }

    /** Renders a single template file and returns its output as a string. */
    private function renderFile(string $tpl, array $data): string
    {
        $file = __DIR__ . '/../templates/' . $tpl;
        if (!file_exists($file)) {
            return '<div class="alert alert-danger">Template not found: '
                . Helper::e($tpl) . '</div>';
        }

        extract($data, EXTR_SKIP);   // make variables available in template scope
        ob_start();
        include $file;
        return (string)ob_get_clean();
    }

    // -----------------------------------------------------------------------
    // Accessors used by controllers
    // -----------------------------------------------------------------------

    public function getVars(): array
    {
        return $this->vars;
    }

    public function makeClient(): Fail2BanClient
    {
        return new Fail2BanClient(
            $this->vars['sudo_path']       ?? '/usr/bin/sudo',
            $this->vars['fail2ban_client'] ?? '/usr/bin/fail2ban-client'
        );
    }

    public function makeJailConfig(): JailConfig
    {
        return new JailConfig(
            $this->vars['jail_local_path'] ?? '/etc/fail2ban/jail.local',
            $this->makeClient()
        );
    }
}
