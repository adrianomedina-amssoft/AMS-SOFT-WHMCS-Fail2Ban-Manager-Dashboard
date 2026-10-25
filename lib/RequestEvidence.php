<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/PhpCgiProbe.php';
require_once __DIR__.'/SqlInjection.php';
require_once __DIR__.'/QueryProbe.php';

/** Parse the structured request only; two decoding passes are a bounded grouping aid. */
final class RequestEvidence
{
    public const NORMAL_PATHS="/\n/clientarea.php\n/robots.txt\n/favicon.ico\n/retired-page\n/index.php\n/login\n/checkout.php\n/license.php";
    public static function normalize(string $target): string {
        if(strlen($target)>8192)return '';
        for($i=0;$i<2;$i++){$decoded=rawurldecode($target);if($decoded===$target)break;$target=$decoded;}
        if(preg_match('/[\x00-\x1f\x7f]/',$target))return '';
        return $target;
    }
    public static function target(string $line): ?string {
        if(preg_match('~^\S+\s+-\s+\S+\s+\[[^\]\r\n]*\]\s+"[A-Z]{3,12} ([^ "\r\n]+) HTTP/~',$line,$m))return self::normalize($m[1]);
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH10244: invalid URI path \((/[^()\r\n]*)\)~',$line,$m))return self::normalize($m[1]);
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01276: Cannot serve directory (/[^\r\n]*?): No matching DirectoryIndex \([^\r\n]*\) found, and server-generated directory index forbidden by Options directive(?:, referer: [^\r\n]*)?$~D',$line,$m))return self::normalize($m[1]);
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\].*?(?:configuration:|not found or unable to stat:)\s*(/[^\r\n]+)~',$line,$m))return self::normalize(explode(', referer: ',$m[1],2)[0]);
        return null;
    }
    public static function nonOffensiveLine(string $line): bool {
        // The explicit request payload outranks ordinary routes and HTTP421.
        if(PhpCgiProbe::fromLine($line)||SqlInjection::fromLine($line))return false;
        if(QueryProbe::route($line)!==null)return false;
        $target=self::target($line);
        $autoindex=(bool)preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01276:~',$line);
        $familyTarget=$autoindex&&$target!==null?preg_replace('~(?:^|/)\.env\.(?:example|sample|dist)(?=/|$)~i','/public-example',$target):$target;
        // A real exploit/secret target takes precedence over an ordinary-route setting.
        if($familyTarget!==null&&AttackFamily::fromTarget($familyTarget)!==null)return false;
        if($target!==null&&preg_match('~(?:^|/)\.(?:aws/(?:credentials|config)|docker/config\.json|ssh/(?:id_rsa|id_ed25519|config)|npmrc|gitlab-ci\.yml|github/workflows/deploy\.yml|azure/accesstokens\.json)(?:$|/)~i',explode('?',$target,2)[0]))return false;
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH02032:~',$line))return true;
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01630:~',$line))return true;
        if(preg_match('~^(?:\[[^\]\r\n]*\]\s*)*?\[client [^\]\r\n]+\]\s+AH01276:~',$line))return true;
        if($target===null)return false;
        if(preg_match('~^\S+ - \S+ \[[^\]]*\] "[^"\r\n]*" 421 (?:\d+|-)~',$line))return true;
        $normal=Database::getConfig('ai_non_offensive_paths',self::NORMAL_PATHS);
        return in_array(explode('?',$target,2)[0],preg_split('/\s+/',trim($normal),-1,PREG_SPLIT_NO_EMPTY),true);
    }
    public static function nonOffensiveOnly(array $s): bool {
        $e=$s['evidence']??$s['samples']??[];
        if(is_string($e))$e=json_decode($e,true)?:[];
        $lines=[];foreach(is_array($e)?$e:[] as $entry){$l=is_array($entry)?($entry['line']??''):$entry;if(is_string($l)&&Safety::sourceIp($l)===($s['ip']??''))$lines[]=$l;}
        return $lines!==[]&&count(array_filter($lines,fn($l)=>self::nonOffensiveLine($l)))===count($lines);
    }
}
