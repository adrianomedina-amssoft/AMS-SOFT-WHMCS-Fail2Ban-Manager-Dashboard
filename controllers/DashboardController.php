<?php
namespace AMS\Fail2Ban\Controllers;

use AMS\Fail2Ban\{DashboardOverview, Router};

class DashboardController
{
    public function __construct(private array $vars, private Router $router) {}

    public function handle(string $action): string
    {
        return $this->router->render('dashboard_overview', ['overview'=>DashboardOverview::read($this->vars)]);
    }
}
