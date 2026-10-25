<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($key,$default=''){
    return $key==='ai_non_offensive_paths'?"/\n/index.php\n/clientarea.php\n/checkout.php\n/login":$default;
}}
require dirname(__DIR__).'/lib/Safety.php';
require dirname(__DIR__).'/lib/AttackFamily.php';
if(in_array('--json',$argv,true)){
    $input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
    echo json_encode(['pattern'=>PhpCgiProbe::pattern(),'lines'=>array_map(fn($line)=>[
        'recognized'=>PhpCgiProbe::fromLine($line),'non_offensive'=>RequestEvidence::nonOffensiveLine($line),
        'family'=>AttackFamily::fromLine($line)],$input['lines'])],JSON_THROW_ON_ERROR);
    exit;
}
$n=0;function check($ok,$why){global $n;if(!$ok)throw new \RuntimeException($why);$n++;}
$target='/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input';
foreach(['198.51.100.77','2001:db8::77'] as $ip)foreach([200,301,403,404,421,500] as $status){
    $line=$ip.' - - ['.date('d/M/Y:H:i:s O').'] "POST '.$target.' HTTP/1.1" '.$status.' 10 "-" "fixture"';
    check(PhpCgiProbe::fromLine($line),'Raw payload missed');check(!RequestEvidence::nonOffensiveLine($line),'Payload downgraded');
    check(AttackFamily::fromLine($line)==='php-cgi-injection','Family missing');
    $item=['ip'=>$ip,'action'=>'ban','evidence'=>[$line]];
    if(RequestEvidence::nonOffensiveOnly($item))$item['action']='monitor';
    check($item['action']==='ban','Production non-offensive downgrade predicate still fires');
}
foreach(['/','/index.php?name=allow_url_include','/?allow_url_include=1&auto_prepend_file=php://input',
    '/?%ADd+allow_url_include%3d0+%ADd+auto_prepend_file%3dphp://input',
    '/?%ADd+auto_prepend_file%3dphp://input','/?%2525ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input'] as $path){
    $line='198.51.100.77 - - [] "POST '.$path.' HTTP/1.1" 421 10 "'.$target.'" "'.$target.'"';
    check(!PhpCgiProbe::fromLine($line),'Incomplete/forged payload recognized');
    check(RequestEvidence::nonOffensiveLine($line),'Normal421lostveto');
}
check(!PhpCgiProbe::target('/'.str_repeat('x',8192).$target),'Oversized target recognized');
echo "PASS: {$n} pure PHP CGI recognition and downgrade predicate checks; no SQL/provider/native\n";
