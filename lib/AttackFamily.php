<?php
namespace AMS\Fail2Ban;
require_once __DIR__.'/RequestEvidence.php';
require_once __DIR__.'/SqlInjection.php';

/** Grouping metadata, never authority to classify or ban a peer. */
final class AttackFamily
{
    public static function fromLine(string $line): ?string
    {
        if(PhpCgiProbe::fromLine($line))return 'php-cgi-injection';
        $target=RequestEvidence::target($line);
        if($target===null)return null;
        return self::fromTarget($target);
    }

    public static function fromTarget(string $target): ?string
    {
        if(SqlInjection::target($target))return 'sql-injection';
        $path=strtolower(explode('?',$target,2)[0]);
        if(preg_match('~(?:^|/)(?:wp-(?:admin|content|includes|json)(?:/|$)|wp-(?:login|config|load)\.php(?:$|/)|xmlrpc\.php(?:$|/))~',$path))return 'wordpress-probe';
        if(preg_match('~(?:^|/)\.env(?:$|[./])~',$path))return 'env-exposure';
        if(preg_match('~(?:^|/)\.git(?:$|/)~',$path))return 'git-exposure';
        if(preg_match('~(?:^|/)\.svn/(?:wc\.db|entries)$~',$path))return 'svn-exposure';
        if(preg_match('~/(?:administrator/manifests/files/joomla\.xml|magento_version|core/install\.php)$~',$path))return 'cms-recon';
        if(preg_match('~(?:^|/)(?:phpmyadmin|phpmyadmin[0-9]+|pma)(?:/|$)~',$path))return 'phpmyadmin-probe';
        if(preg_match('~union\s+(?:all\s+)?select|sleep\s*\(|benchmark\s*\(|or\s+1\s*=\s*1~i',$target))return 'sql-injection';
        if(preg_match('~\.\./|/etc/passwd~i',$target))return 'path-traversal';
        if(preg_match('~(?:;|\|)\s*(?:wget|curl|sh|bash)\b~i',$target))return 'command-injection';
        return null;
    }

    public static function forSuggestion(array $s): string
    {
        $e=$s['evidence']??[];if(is_string($e))$e=json_decode($e,true)?:[];
        $families=[];
        foreach($e as $line)if(is_string($line)&&Safety::sourceIp($line)===($s['ip']??'')){
            $family=self::fromLine($line);if($family===null)return 'pattern:'.($s['_pattern']??$s['pattern']??hash('sha256',$s['failregex']??''));
            $families[$family]=true;
        }
        return count($families)===1?array_key_first($families):'pattern:'.($s['_pattern']??$s['pattern']??hash('sha256',$s['failregex']??''));
    }

    public static function format(string $source): string
    {
        return str_contains(basename($source),'access')?'access':(str_contains(basename($source),'error')?'error':'auth');
    }
}
