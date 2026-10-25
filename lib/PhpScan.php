<?php
namespace AMS\Fail2Ban;

/** Scheduling metadata only; a ban requires individually validated failed requests. */
final class PhpScan
{
    public const KEYS=['ai_php_scan_enabled','ai_php_scan_min_confidence','ai_php_scan_min_events','ai_php_scan_min_targets','ai_php_scan_window_minutes','ai_php_scan_history_enabled','ai_php_scan_history_rows'];
    private const NORMAL=['index.php','clientarea.php','cart.php','checkout.php','configuration.php','config.php','license.php',
        'login.php','logout.php','register.php','contact.php','submitticket.php','viewticket.php','viewinvoice.php',
        'announcements.php','knowledgebase.php','download.php','downloads.php','dl.php','cron.php','api.php',
        'addonmodules.php','automationstatus.php','callback.php','invoice.php','creditcard.php','viewquote.php',
        'announcementsrss.php','upgrade.php','viewemail.php','networkissues.php','networkissuesrss.php','dologin.php',
        'domainchecker.php','unsubscribe.php','link.php','aff.php','banned.php','whois.php','affiliates.php','pwreset.php',
        'configuressl.php','supporttickets.php','serverstatus.php','downloadnfse.php','init.php','custom_page_template.php'];
    public static function enabled(): bool {
        return (int)Database::getConfig('schema_version','0')>=33&&Policy::number('ai_php_scan_enabled')===1;
    }
    public static function pattern(): string {return hash('sha256','individual-php-scan-v1');}
    public static function catalogPattern(string $pattern): bool {return hash_equals(self::pattern(),$pattern);}
    public static function grouped(string $pattern): bool {return self::enabled()&&self::catalogPattern($pattern);}
    public static function target(string $line,bool $context=false): ?string {
        // Complete combined access log only. UA, referrer and error text are not targets.
        if(strlen($line)>65536||!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(GET|HEAD) ([^ "\r\n]+) HTTP/\d(?:\.\d)?" (\d{3}) (?:\d+|-) "[^"\r\n]*" "[^"\r\n]*"$~D',$line,$m))return null;
        if(!in_array((int)$m[3],$context?[301,302,307,308,403,404]:[403,404],true))return null;
        $target=RequestEvidence::normalize($m[2]);$path=strtolower(explode('?',$target,2)[0]);
        if(!preg_match('~^/(?:[a-z0-9_-]{1,80}/){0,12}[a-z0-9_-]{1,80}\.php$~D',$path)
            ||in_array(basename($path),self::NORMAL,true)||AttackFamily::fromTarget($target)!==null
            ||RequestEvidence::nonOffensiveLine($line))return null;
        return $path;
    }
    public static function signature(string $line,string $ip): ?string {
        if(Safety::sourceIp($line)!==$ip||self::target($line,true)===null||BehaviorStore::eventTime($line)===null)return null;
        return hash('sha256',preg_replace('~^(\S+ - \S+ )\[[^\]\r\n]+\]~','$1[]',$line));
    }
    public static function samples(array $events): array {
        // Prefer newest failures at distinct targets, then optional redirect context.
        $chosen=[];$paths=[];$ids=[];$ordered=array_reverse($events);
        foreach(['distinct','repeat','context'] as $mode)foreach($ordered as $event){
            $context=$mode==='context';
            $path=self::target($event['line']??'',$context);
            if($path===null||($mode!=='repeat'&&isset($paths[$path]))||isset($ids[$event['id']??'']))continue;
            $paths[$path]=true;$ids[$event['id']]=true;$chosen[]=$event;
            if(count($chosen)===5)return array_reverse($chosen);
        }
        return array_reverse($chosen);
    }
    public static function stats(array $events,string $ip,int $cutoff): array {
        $seen=[];$targets=[];
        foreach($events as $event){
            $line=$event['evidence']??$event['line']??'';$time=BehaviorStore::eventTime($line);
            if(!$time||$time<$cutoff||$time>time()+300||Safety::sourceIp($line)!==$ip)continue;
            $target=self::target($line);if($target===null)continue;
            $seen[hash('sha256',$line)]=true;$targets[$target]=true;
        }
        return ['events'=>count($seen),'targets'=>count($targets)];
    }
    public static function priority(array $row): bool {
        if(!self::grouped($row['pattern']??''))return false;
        $samples=$row['samples']??[];if(is_string($samples))$samples=json_decode($samples,true)?:[];
        return self::stats($samples,$row['ip'],RecentActivity::cutoff())['targets']>=2;
    }
}
