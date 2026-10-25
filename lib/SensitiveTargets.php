<?php
namespace AMS\Fail2Ban;
/** Grouping/priority metadata only. No classification or blocking authority. */
final class SensitiveTargets
{
    public static function target(string $line): ?string {
        $path=null;
        if(preg_match('~"(?:GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) ([^ ]+) HTTP/~',$line,$m))$path=explode('?',$m[1],2)[0];
        elseif(preg_match('~^\\[[^\\r\\n]+\\].*?\\[client [^\\]]+\\].*?(?:configuration:|not found or unable to stat:)\\s*(/[^\\r\\n]+)~',$line,$m))$path=$m[1];
        if($path===null)return null;
        $path=strtolower(rawurldecode($path));
        if(preg_match('/[\\x00-\\x20\\x7f]/',$path))return null;
        $path=preg_replace('~/+~','/',$path);
        // Ignore directory/query/encoding variants of the same sensitive target.
        if(preg_match('~(?:^|/)(\\.env(?:\\.[a-z0-9_.-]+)?)(?:$|/)~',$path,$m)
            &&!preg_match('~^\\.env\\.(?:example|sample|dist)(?:\\.|$)~',$m[1]))return 'env:'.$m[1];
        foreach(['.git/head','.git/config','.svn/wc.db','.ssh/id_rsa','.ssh/id_ed25519','.ssh/config',
            '.gitlab-ci.yml','.github/workflows/deploy.yml','.azure/accesstokens.json','wp-config.php'] as $target)
            if(str_ends_with($path,'/'.$target)||$path===$target)return $target;
        return null;
    }
    public static function priority(array $row): bool {
        foreach(DecisionProtection::lines($row) as $line)if(self::target($line)!==null)return true;
        return false;
    }
}
