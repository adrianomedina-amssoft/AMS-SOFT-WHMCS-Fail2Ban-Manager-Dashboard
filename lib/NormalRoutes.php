<?php
namespace AMS\Fail2Ban;

/** One literal catalogue; never a prefix rule or an IP whitelist. */
final class NormalRoutes
{
    public static function paths(?string $text=null): array
    {
        $text=$text??Database::getConfig('ai_non_offensive_paths',RequestEvidence::NORMAL_PATHS);
        $paths=array_values(array_unique(preg_split('/\s+/',trim($text),-1,PREG_SPLIT_NO_EMPTY)));
        if(count($paths)>50)throw new \InvalidArgumentException('No máximo 50 rotas normais.');
        foreach($paths as $path)if(strlen($path)>200||!preg_match('~^/[A-Za-z0-9_./-]*$~D',$path))
            throw new \InvalidArgumentException('Use caminhos literais, sem query, encoding ou regex.');
        return $paths;
    }

    public static function sync(?string $text=null): bool
    {
        $paths=self::paths($text);
        $file=tempnam('/tmp','amsfb_normal_');
        if($file===false)return false;
        try {
            if(file_put_contents($file,json_encode(['paths'=>$paths],JSON_THROW_ON_ERROR))===false)return false;
            return !empty(Privileged::run(['sync-normal-paths',$file])['success']);
        } finally {@unlink($file);}
    }
}
