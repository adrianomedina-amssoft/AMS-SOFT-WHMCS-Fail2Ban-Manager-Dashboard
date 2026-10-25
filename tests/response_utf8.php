<?php
namespace WHMCS\Database {
    class Capsule {
        public static array $rows=[];
        public static function table($table) {
            if ($table!=='mod_amssoft_fail2ban_analysis_batches') throw new \RuntimeException('Unexpected table');
            return new class {
                public function insert($row) { Capsule::$rows[]=$row; return true; }
            };
        }
    }
}
namespace AMS\Fail2Ban {
    if(PHP_SAPI!=='cli')exit(1);
    class Database { public static function getConfig($key,$default='') { return $key==='schema_version'?'34':$default; } }
    class DecisionMemory { public static function policyFingerprint(): string {return hash('sha256','pure-fixture');} }
    require dirname(__DIR__).'/lib/Router.php';
    $ai=(new \ReflectionClass(AIAnalyzer::class))->newInstanceWithoutConstructor();
    $parse=new \ReflectionMethod(AIAnalyzer::class,'parseResponse');
    $filter=new \ReflectionMethod(AIAnalyzer::class,'parseFilterResponse');
    $encode=new \ReflectionMethod(AnalysisWork::class,'encode');
    $checks=0;
    function utfCheck($ok,$why) {global $checks;if(!$ok)throw new \RuntimeException($why);$checks++;}
    $line='198.51.100.81 - - [21/Oct/2026:03:00:00 -0300] "GET /.env HTTP/1.1" 404 10 "-" "UTF8 ç 😀"';
    $proof=['id'=>hash('sha256',$line),'line'=>$line,'ip'=>'198.51.100.81'];
    $base=['ip'=>'198.51.100.81','action'=>'ban','confidence'=>99,'threat'=>'Ameaça','reason'=>'Prova individual',
        'evidence'=>[$line],'suggested_rule'=>'','filter_name'=>'fixture-env','failregex'=>'^<HOST> fixture$'];
    foreach(['threat'=>128,'reason'=>1000,'suggested_rule'=>4000] as $field=>$limit)
    foreach(['ç','界','😀'] as $char)
    foreach([-1,0,1,20] as $extra){
        $input=$base;$input[$field]='<b>'.str_repeat('a',$limit-1).$char.str_repeat('z',max(0,$extra)).'</b>';
        if($extra===-1)$input[$field]=str_repeat('a',$limit-strlen($char)).$char;
        $raw=$parse->invoke($ai,json_encode([$input],JSON_THROW_ON_ERROR));
        utfCheck(mb_check_encoding($raw[0][$field],'UTF-8'),'InvalidUTF8 '.$field);
        utfCheck(strlen($raw[0][$field])<=$limit,'Byte limit '.$field);
        utfCheck($raw[0][$field]===mb_strcut(strip_tags($input[$field]),0,$limit,'UTF-8'),'Unexpected text change');
        $id=AnalysisWork::saveBatch([['id'=>'fixture','ip'=>$base['ip']]],[$base['ip']=>[$proof]],[], $raw);
        $saved=json_decode(end(\WHMCS\Database\Capsule::$rows)['payload'],true,512,JSON_THROW_ON_ERROR);
        utfCheck(strlen($id)===64&&$saved['raw']===$raw,'Checkpoint mismatch');
        utfCheck($saved['proofs'][$base['ip']][0]===$proof&&$saved['raw'][0]['evidence']===[$line],'Evidence changed');
    }
    foreach([str_repeat('a',1000),str_repeat('a',998).'ç',str_repeat('a',996).'😀','^<HOST> café$'] as $regex){
        $input=$base;$input['failregex']=$regex;
        $raw=$parse->invoke($ai,json_encode([$input],JSON_THROW_ON_ERROR));
        utfCheck($raw[0]['failregex']===$regex,'In-limit regex changed');
        utfCheck(is_array($filter->invoke($ai,json_encode(['filter_name'=>'fixture','failregex'=>$regex],JSON_THROW_ON_ERROR))),'In-limit standalone refused');
        AnalysisWork::saveBatch([],[],[],$raw);
    }
    foreach([str_repeat('a',999).'ç',str_repeat('a',999).'😀',str_repeat('a',1001),['not-a-string'],17] as $regex){
        $input=$base;$input['failregex']=$regex;
        $raw=$parse->invoke($ai,json_encode([$input],JSON_THROW_ON_ERROR));
        utfCheck($raw[0]['failregex']==='','Regex truncated/accepted instead of refused');
        utfCheck($filter->invoke($ai,json_encode(['filter_name'=>'fixture','failregex'=>$regex],JSON_THROW_ON_ERROR))===null,'Standalone unsafe regex accepted');
        AnalysisWork::saveBatch([],[],[],$raw);
    }
    $input=$base;foreach(['threat','reason','suggested_rule'] as $field)$input[$field]=['unexpected'];
    utfCheck(is_string($encode->invoke(null,['raw'=>$parse->invoke($ai,json_encode([$input],JSON_THROW_ON_ERROR))])),'Unexpected text type broke encoding');
    try {$encode->invoke(null,['proofs'=>["\xAD"]]);utfCheck(false,'Invalid evidence was rewritten');}
    catch(\JsonException $e){utfCheck($e->getCode()===JSON_ERROR_UTF8,'Wrong invalid evidence error');}
    try {$encode->invoke(null,['raw'=>str_repeat('x',AnalysisWork::MAX_PAYLOAD+1)]);utfCheck(false,'Payload cap bypass');}
    catch(\LengthException $e){$checks++;}
    echo "PASS: {$checks} UTF8/parser/checkpoint/regex boundary checks; memory-only, no SQL/provider/native\n";
}
