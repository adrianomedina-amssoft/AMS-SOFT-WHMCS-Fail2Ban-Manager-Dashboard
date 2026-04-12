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

        $shared['system_warnings'] = $this->checkSystemRequirements();

        $data   = array_merge($shared, $data);
        $content = $this->renderFile($template . '.tpl', $data);

        $data['content'] = $content;
        return $this->renderFile('layout.tpl', $data);
    }

    /**
     * Verifica requisitos de sistema e retorna lista de avisos para exibir no layout.
     * Cada aviso é ['level' => 'warning|danger', 'message' => '...', 'fix' => '...'].
     */
    private function checkSystemRequirements(): array
    {
        $warnings = [];

        $sudoersFile = '/etc/sudoers.d/amssoft_fail2ban';

        // Arquivos sudoers devem ser root:root 0440 — www-data não consegue lê-los.
        // Verificamos existência e depois testamos funcionalmente via sudo ping.
        if (!file_exists($sudoersFile)) {
            $warnings[] = [
                'level'   => 'danger',
                'message' => 'Arquivo de sudoers não encontrado: <code>' . $sudoersFile . '</code>. '
                           . 'O módulo não conseguirá executar comandos do fail2ban.',
                'fix'     => 'cp ' . escapeshellarg(dirname(__DIR__) . '/setup/sudoers/amssoft_fail2ban')
                           . ' ' . escapeshellarg($sudoersFile)
                           . ' &amp;&amp; chmod 0440 ' . escapeshellarg($sudoersFile),
            ];
            return $warnings;
        }

        // Verificar se as regras sudo estão funcionando (teste funcional)
        $sudoPath        = '/usr/bin/sudo';
        $fail2banClient  = '/usr/bin/fail2ban-client';
        $pingOutput      = shell_exec($sudoPath . ' ' . $fail2banClient . ' ping 2>&1');
        $sudoWorks       = ($pingOutput !== null && str_contains($pingOutput, 'pong'));

        if (!$sudoWorks) {
            $warnings[] = [
                'level'   => 'warning',
                'message' => 'O arquivo <code>' . $sudoersFile . '</code> existe, mas o sudo não está funcionando corretamente. '
                           . 'Verifique se as regras estão atualizadas e válidas.',
                'fix'     => 'cp ' . escapeshellarg(dirname(__DIR__) . '/setup/sudoers/amssoft_fail2ban')
                           . ' ' . escapeshellarg($sudoersFile)
                           . ' &amp;&amp; chmod 0440 ' . escapeshellarg($sudoersFile)
                           . ' &amp;&amp; visudo -c',
            ];
        }

        // Verifica permissões de jail.local — visível em todas as páginas, não só em Jails.
        $jailLocalPath = $this->vars['jail_local_path'] ?? '/etc/fail2ban/jail.local';
        $jailConfig    = new JailConfig($jailLocalPath);
        $permError     = $jailConfig->checkPermissions();
        if ($permError !== null) {
            $warnings[] = [
                'level'   => 'danger',
                'message' => htmlspecialchars($permError, ENT_QUOTES, 'UTF-8'),
                'fix'     => 'chown root:www-data ' . escapeshellarg($jailLocalPath)
                           . ' &amp;&amp; chmod 0664 ' . escapeshellarg($jailLocalPath),
            ];
        }

        return $warnings;
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

    public function makeFilterManager(): FilterManager
    {
        return new FilterManager(
            '/etc/fail2ban/filter.d/',
            $this->makeJailConfig(),
            $this->makeClient()
        );
    }
}
