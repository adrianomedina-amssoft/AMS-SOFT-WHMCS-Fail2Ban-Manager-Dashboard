<?php
if(PHP_SAPI!=='cli')exit(1);
require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__,4).'/configuration.php';
require dirname(__DIR__,4).'/vendor/autoload.php';
require dirname(__DIR__).'/lib/Router.php';
use AMS\Fail2Ban\{Router,Policy,Helper};
$capsule=new WHMCS\Database\Capsule();$capsule->addConnection(['driver'=>'mysql','host'=>$db_host,'database'=>$db_name,
    'username'=>$db_username,'password'=>$db_password,'charset'=>'utf8mb4','collation'=>'utf8mb4_unicode_ci','prefix'=>'']);
$capsule->setAsGlobal();$capsule->bootEloquent();
$_SESSION=['adminid'=>1];$_GET['action']='protection';$_SERVER['REQUEST_METHOD']='GET';
$router=new Router(['modulelink'=>'addonmodules.php?module=amssoft_fail2ban','sudo_path'=>'/usr/bin/sudo','fail2ban_client'=>'/usr/bin/fail2ban-client']);
$html=$router->dispatch('protection');
$dom=new DOMDocument();libxml_use_internal_errors(true);$dom->loadHTML($html);$xp=new DOMXPath($dom);$checks=0;
foreach(Policy::fields() as $key=>$field){if($xp->query('//*[@name="'.$key.'"]')->length!==1)throw new RuntimeException('Missing/duplicate policy field '.$key);$checks++;}
if($xp->query('//*[@id="maintenance-queue" and @disabled]')->length!==1)throw new RuntimeException('Maintenance not gated by preview');$checks++;
if($xp->query('//input[@name="csrf_token"]')->length!==1)throw new RuntimeException('CSRF field absent');$checks++;
foreach($xp->query('//script[not(@src)]') as $script) {
    $tmp=tempnam('/tmp','amsfb-js-');
    try {
        file_put_contents($tmp,$script->textContent);exec('node --check '.escapeshellarg($tmp).' 2>&1',$output,$code);
        if($code!==0)throw new RuntimeException('Inline JS syntax: '.implode("\n",$output));$checks++;
    } finally {unlink($tmp);}
}
$payload='" onmouseover="alert(1) <img src=x onerror=alert(1)>';
$test=new DOMDocument();$test->loadHTML('<button data-evidence="'.Helper::e($payload).'">test</button>');
if($test->getElementsByTagName('img')->length||$test->getElementsByTagName('button')->item(0)->hasAttribute('onmouseover'))throw new RuntimeException('Attribute escaping');$checks++;
echo "PASS: {$checks} PHP-rendered DOM/JS checks; synthetic admin session, not an authenticated browser test\n";
