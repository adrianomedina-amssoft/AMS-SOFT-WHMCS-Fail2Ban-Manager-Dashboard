<?php
namespace AMS\Fail2Ban;

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

// Deliberately no WHMCS bootstrap, SQL connection or provider calls.
class Database
{
    public static array $config = [];
    public static function getConfig($key, $default = '') { return self::$config[$key] ?? $default; }
    public static function setConfig($key, $value) { self::$config[$key] = $value; }
}

require_once dirname(__DIR__).'/lib/CycleBudget.php';
require_once dirname(__DIR__).'/lib/CycleBudgetExceeded.php';
require dirname(__DIR__) . '/lib/Router.php';
$checks = 0;
function check(bool $ok, string $label): void {
    global $checks;
    if (!$ok) throw new \RuntimeException('FAIL: ' . $label);
    $checks++;
}

$telemetry=BehaviorStore::parseTelemetryLine('2026-10-11 20:00:00,123 fail2ban.actions [123]: NOTICE [ai-bans] Ban 2001:db8::10');
check($telemetry['action']==='daemon_ban'&&$telemetry['ip']==='2001:db8::10','IPv6 daemon telemetry distinct from attack evidence');
check(BehaviorStore::parseTelemetryLine('198.51.100.10 - - request')===null,'Request is not daemon telemetry');
foreach(['2026-10-12T14:00:00Z','2026-10-12T14:00:00.123456+00:00','2026-10-12T11:00:00-03:00','2026-10-12T19:30:00+05:30'] as $stamp) {
    check(BehaviorStore::eventTime($stamp.' host sshd[1]: fixture')===strtotime('2026-10-12T14:00:00Z'),'ISO timestamp respects explicit timezone '.$stamp);
}
check(BehaviorStore::eventTime('2026-10-12 11:00:00 WHMCS login failed')===strtotime('2026-10-12 11:00:00'),'Local timestamp compatibility');
check(BehaviorStore::parseTelemetryLine('2026-10-11 20:00:00,123 fail2ban.actions [123]: NOTICE [test] Unban 198.51.100.10')['action']==='daemon_unban','Unban telemetry');
$errorLine='[Mon Oct 12 13:00:00.123456 2026] [core:error] [client 198.51.100.10:1234] denied /probe/[01/Jan/2030:00:00:00 +0000]';
check(BehaviorStore::eventTime($errorLine)===strtotime('2026-10-12 13:00:00'),'Apache error date wins over injected access date');
check(BehaviorStore::eventTime('2026-10-12T14:00:00Z host sshd[1]: [01/Jan/2030:00:00:00 +0000]')===1791813600,'ISO date wins over injected access date');
check(BehaviorStore::eventTime('unstructured [01/Jan/2030:00:00:00 +0000]')===null,'Payload date alone never proves event time');
check(BehaviorStore::eventTime('198.51.100.10 - user [12/Oct/2026:14:00:00 +0000] "GET / HTTP/1.1" 200 1')===1791813600,'Access header date with authenticated user');


foreach (['127.0.0.1','127.3.4.5','0.0.0.0','0.0.0.1','::','::1','::ffff:127.0.0.1','invalid'] as $ip) {
    check(!Safety::canBan($ip), 'protected IP ' . $ip);
}
check(Safety::canBan('203.0.113.7'), 'ordinary IPv4 accepted');
check(Safety::canBan('2001:db8::7'), 'ordinary IPv6 accepted');
check(Safety::filterName('amsfb-amsfb-Apache---Probe') === 'apache-probe', 'canonical prefix');
check(Safety::filterName('amsfb-') === '', 'empty prefix rejected');
check(strlen('f2b-' . Safety::actionName(str_repeat('a', 64))) < 29, 'bounded chain');
check(Safety::actionName('a') !== Safety::actionName('b'), 'distinct chains');
check(Safety::isWhitelisted('203.0.113.8',['203.0.113.0/24']), 'IPv4 CIDR');
check(!Safety::isWhitelisted('192.0.2.8',['203.0.113.0/24']), 'CIDR outside');
check(Safety::isWhitelisted('2001:db8::8',['2001:db8::/32']), 'IPv6 CIDR');
check(!Safety::isWhitelisted('2001:db9::8',['2001:db8::/32']), 'IPv6 outside');
check(Safety::isWhitelisted('2001:db8::8',['2001:0db8:0:0:0:0:0:8']), 'equivalent IPv6 whitelist');
check(count(Safety::evidence(['2001:0db8:0:0:0:0:0:8 - - test'], '2001:db8::8')) === 1, 'equivalent IPv6 evidence');

$normal = '198.51.100.10 - - [11/Oct/2026:17:00:00 -0300] "GET /clientarea.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"';
$attack = '203.0.113.7 - - [11/Oct/2026:17:00:01 -0300] "GET /.env HTTP/1.1" 404 100 "-" "scanner"';
$method = new \ReflectionMethod(AutoBanEngine::class, 'heuristicFallback');
$suggestion = $method->invoke(null, [$normal, $attack]);
check($suggestion['ip'] === '203.0.113.7', 'heuristic tied to suspicious peer');
check($suggestion['evidence'] === [$attack], 'only relevant evidence');
check($suggestion['_heuristic'] === true, 'heuristic requires review');
check($method->invoke(null, [$normal, $normal]) === null, 'benign batch no heuristic');
check(Safety::sourceIp('[x] [client 203.0.113.7] denied') === '203.0.113.7', 'Apache peer without port');
check(Safety::sourceIp('[x] [client 203.0.113.7:1234] denied') === '203.0.113.7', 'Apache peer with port');
check(Safety::sourceIp('[x] [client 2001:db8::7:1234] denied') === '2001:db8::7', 'Apache IPv6 peer/port');
check(Safety::sourceIp('untrusted text from 203.0.113.7') === null, 'unstructured payload not a peer');
check(Safety::sourceIp(str_replace('Mozilla/5.0','[client 203.0.113.7]',$normal))==='198.51.100.10','Access peer wins over forged client payload');
check(Safety::sourceIp('[x] [client 198.51.100.10:1234] denied WHMCS login failed from 203.0.113.7 area=client')==='198.51.100.10','Error message cannot forge a WHMCS peer');
check(Safety::sourceIp('[x] AH001 denied /probe/[client 203.0.113.7]')===null,'Client token in message is not Apache peer');
check(Safety::sourceIp('2026-10-12T11:00:00-03:00 host sshd[1]: Failed password for x from 198.51.100.10 port 123 ssh2')==='198.51.100.10','Structured SSH peer');
check(Safety::sourceIp('2026-10-12 11:00:00 WHMCS login failed from 198.51.100.10 area=client')==='198.51.100.10','Structured WHMCS peer');
$bound = Safety::bindSuggestions([['ip'=>'198.51.100.20'],['ip'=>'203.0.113.7']], [$normal,$attack]);
check(count($bound) === 1 && $bound[0]['ip'] === '203.0.113.7', 'invented IP rejected');
check(LogViewer::filterLinesByIPs([$normal,$attack],['198.51.100.0/24']) === [$attack], 'CIDR prefilter');
$viewer = new LogViewer();
check(!$viewer->isValidPath('/var/www/html/whmcs/configuration.php'), 'credentials path denied');
check(!$viewer->isValidPath('/tmp/anything.log'), 'temporary log path denied');
check(!$viewer->isValidPath('/var/log/../configuration.php'), 'traversal denied');
$ips = array_column($viewer->extractIPs(['::1 2001:db8::5 203.0.113.7']), 'ip');
check(in_array('::1',$ips,true) && in_array('2001:db8::5',$ips,true), 'compressed IPv6 extraction');

$_SESSION = ['adminid'=>1];
$token = Helper::csrfToken();
check(Helper::checkCsrf($token) && Helper::checkCsrf($token), 'concurrent CSRF requests');
$response = json_decode((new Router([]))->handleAjax('logviewer','fetch_lines',['csrf_token'=>'stale']),true);
check($response['success'] === false && $response['csrf_token'] === $token, 'CSRF recovery');

$analyzer = (new \ReflectionClass(AIAnalyzer::class))->newInstanceWithoutConstructor();
$parse = new \ReflectionMethod(AIAnalyzer::class, 'parseResponse');
foreach (['[]','{"suggestions":[]}',"```json\n[]\n```"] as $json) {
    check($parse->invoke($analyzer,$json) === [], 'valid JSON accepted');
}
foreach (['{}','{"unexpected":[]}','null','[','not JSON'] as $json) {
    $rejected = false;
    try { $parse->invoke($analyzer,$json); } catch (InvalidResponseException $e) { $rejected = true; }
    check($rejected, 'invalid schema rejected');
}
$result = FilterManager::testValidateFailregex();
check($result['fail'] === 0, 'legacy filter regression');

$dir = sys_get_temp_dir() . '/amsfb-test-' . bin2hex(random_bytes(8));
mkdir($dir,0700);
try {
    $path = $dir . '/jail.local';
    file_put_contents($path, "[DEFAULT]\naction = first\n    second\n[existing]\n    enabled = true\n    maxretry = 5\n");
    $config = new JailConfig($path);
    $data = $config->readJailLocal();
    check($data['DEFAULT']['action'] === "first\nsecond", 'multiline parser');
    check($data['existing']['maxretry'] === '5', 'indented option parser');
    check($config->addJail('amsfb-new', ['enabled'=>'false','logpath'=>'/var/log/auth.log']), 'atomic create');
    check(!$config->addJail('amsfb-new', ['enabled'=>'true']), 'duplicate create rejected');
    check($config->saveJail('existing', ['maxretry'=>'7']), 'atomic update');
    check(isset($config->readJailLocal()['amsfb-new']), 'unrelated jail preserved');
    check($config->removeJail('amsfb-new'), 'explicit remove');
} finally {
    foreach (glob($dir . '/*') as $file) unlink($file);
    foreach (glob($dir . '/.amsfb-*') as $file) unlink($file);
    rmdir($dir);
}
define('WHMCS',true);
require dirname(__DIR__) . '/amssoft_fail2ban.php';
check(amssoft_fail2ban_deactivate()['status'] === 'success', 'deactivate preserves DB');
check(Database::$config['ai_auto_enabled'] === '0', 'deactivate stops automation');
echo "PASS: {$checks} checks\n";
