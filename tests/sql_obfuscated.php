<?php
namespace AMS\Fail2Ban;
if(PHP_SAPI!=='cli')exit(1);
class Database {public static function getConfig($k,$d=''){return ['schema_version'=>'37','ai_non_offensive_paths'=>"/index.php\n/cart.php\n/modules/addons/RSThemes/src/Api/clientApi.php"][$k]??$d;}}
require dirname(__DIR__).'/lib/Router.php';
$lines=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
echo json_encode(['pattern'=>SqlInjection::obfuscatedPattern(),'rows'=>array_map(fn($line)=>[
    'sql'=>SqlInjection::fromLine($line),'family'=>AttackFamily::fromLine($line),'php_path'=>PhpScan::target($line),'normal'=>RequestEvidence::nonOffensiveLine($line)
],$lines)]);
