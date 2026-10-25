<?php
namespace AMS\Fail2Ban;

/** Closed scheduling catalogue. Recognition alone never authorizes a ban. */
final class ProbeApplications
{
    public const CATALOG=[
        'wordpress'=>['/wp-json','/wp-json/'],
        'exchange'=>['/owa/','/owa','/ecp/','/ecp','/owa/auth/errorfe.aspx',
            '/ecp/current/exporttool/microsoft.exchange.ediscovery.exporttool.application','/owa/auth/logon.aspx'],
        'servlet'=>['/login.do','/showlogin.cc'],
        'telerik'=>['/telerik.web.ui.webresource.axd'],
        'servu'=>['/webinterface/','/webinterface'],
        'coldfusion'=>['/cf_scripts/scripts/ajax/ckeditor/ckeditor.js'],
        'zabbix'=>['/zabbix/favicon.ico'],
        'sitecore'=>['/sitecore/shell/sitecore.version.xml'],
        'solr'=>['/solr/','/solr/admin/info/system','/solr/admin/cores'],
        'sugarcrm'=>['/sugar_version.json'],
        'qnap'=>['/cgi-bin/authlogin.cgi'],
        'spring'=>['/actuator/health','/actuator/env'],
        'vmware'=>['/developmentserver/metadatauploader'],
        'ivanti'=>['/dana-na/nc/nc_gina_ver.txt','/dana-cached/hc/hostcheckerinstaller.osx','/dana-na/auth/url_default/welcome.cgi'],
        'globalprotect'=>['/global-protect/prelogin.esp','/ssl-vpn/prelogin.esp'],
        'rdweb'=>['/rdweb','/rdweb/pages/en-us/login.aspx'],
    ];
    public const LEGACY_GROUPS=['wordpress','exchange','servlet','telerik','servu','coldfusion','zabbix'];
    // Frozen ordering: historical hashes and v2 bitmap positions must never move.
    public const V1_GROUPS=['wordpress','exchange','servlet','telerik','servu','coldfusion','zabbix',
        'sitecore','solr','sugarcrm','qnap','spring','vmware'];
    public const GROUPS=[...self::V1_GROUPS,'ivanti','globalprotect','rdweb'];
    public const KEYS=['ai_application_probe_enabled','ai_application_probe_groups','ai_application_probe_min_confidence','ai_application_probe_min_events','ai_application_probe_min_apps','ai_application_probe_window_minutes'];
    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=28&&Policy::number('ai_application_probe_enabled')===1;}
    public static function application(string $line,?array $groups=null): ?string {
        // Access requests only. Error/referrer/UA text cannot select a target.
        if(!preg_match('~^\S+ - \S+ \[[^\]\r\n]+\] "(?:GET|HEAD|POST) ([^ "\r\n]+) HTTP/~',$line,$m))return null;
        $target=RequestEvidence::normalize($m[1]);if($target==='')return null;
        $path=strtolower(explode('?',$target,2)[0]);
        foreach($groups??self::GROUPS as $group)if(in_array($path,self::CATALOG[$group]??[],true))return $group;
        return null;
    }
    public static function groups(): array {return preg_split('/\s+/',trim(Database::getConfig('ai_application_probe_groups',implode("\n",self::GROUPS))),-1,PREG_SPLIT_NO_EMPTY);}
    public static function pattern(array $groups): string {
        sort($groups,SORT_STRING);
        if(!array_diff($groups,self::V1_GROUPS))return hash('sha256','application-probe-v1|'.implode('|',$groups));
        if(array_diff($groups,self::GROUPS)||count($groups)!==count(array_unique($groups)))throw new \InvalidArgumentException('Unknown or duplicate application group');
        $bits=0;foreach(self::GROUPS as $i=>$group)if(in_array($group,$groups,true))$bits|=1<<$i;
        // 64 hex chars fit the existing schema. The checksum is identification,
        // never evidence/authority; native validation remains mandatory.
        return 'a550'.sprintf('%04x',$bits).substr(hash('sha256','application-probe-v2|'.implode('|',$groups)),0,56);
    }
    public static function grouped(string $pattern): bool {return self::enabled()&&hash_equals(self::pattern(self::groups()),$pattern);}
    public static function catalogPattern(string $pattern): bool {
        if(strlen($pattern)===64&&str_starts_with($pattern,'a550')&&ctype_xdigit($pattern)){
            $bits=hexdec(substr($pattern,4,4));$groups=[];
            foreach(self::GROUPS as $i=>$group)if($bits&(1<<$i))$groups[]=$group;
            if(array_diff($groups,self::V1_GROUPS)&&hash_equals(self::pattern($groups),$pattern))return true;
        }
        // Bound compatibility work to the original 13-group catalogue forever.
        static $patterns=null;if($patterns===null){$patterns=[];$count=count(self::V1_GROUPS);
            for($bits=1;$bits<(1<<$count);$bits++){$groups=[];for($i=0;$i<$count;$i++)if($bits&(1<<$i))$groups[]=self::V1_GROUPS[$i];$patterns[self::pattern($groups)]=true;}
        }
        return isset($patterns[$pattern]);
    }
    public static function signature(string $line,string $ip): ?string {
        if(Safety::sourceIp($line)!==$ip||self::application($line,self::groups())===null||BehaviorStore::eventTime($line)===null)return null;
        return hash('sha256',preg_replace('~^(\S+ - \S+ )\[[^\]\r\n]+\]~','$1[]',$line));
    }
    public static function samples(array $events): array {
        usort($events,fn($a,$b)=>(($b['time']??0)<=>($a['time']??0))?:strcmp($b['id']??'',$a['id']??''));
        $chosen=[];$apps=[];$paths=[];$ids=[];$lines=[];$bytes=2;
        foreach(['application','target','recent'] as $mode)foreach($events as $e){
            $line=$e['line']??'';$id=$e['id']??'';$app=self::application($line,self::groups());
            if($app===null||$id===''||!empty($e['truncated'])||isset($ids[$id]))continue;
            $path=strtolower(explode('?',RequestEvidence::target($line)??'',2)[0]);
            $hash=hash('sha256',$line);
            if(isset($lines[$hash])||($mode==='application'&&isset($apps[$app]))||($mode==='target'&&isset($paths[$path])))continue;
            $size=strlen(json_encode($e,JSON_INVALID_UTF8_SUBSTITUTE))+1;
            if($bytes+$size>262144)continue;
            $bytes+=$size;$ids[$id]=$lines[$hash]=$apps[$app]=$paths[$path]=true;$chosen[]=$e;
            if(count($chosen)===5)break 2;
        }
        usort($chosen,fn($a,$b)=>(($a['time']??0)<=>($b['time']??0))?:strcmp($a['id'],$b['id']));
        return $chosen;
    }
    public static function stats(array $events,string $ip,?int $cutoff=null): array {
        $seen=[];$apps=[];$cutoff=$cutoff??max(RecentActivity::cutoff(),time()-Policy::number('ai_application_probe_window_minutes')*60);
        foreach($events as $e){$line=$e['line']??$e['evidence']??'';$t=BehaviorStore::eventTime($line);
            if(!$t||$t<$cutoff||$t>time()+300||Safety::sourceIp($line)!==$ip)continue;
            $app=self::application($line,self::groups());if($app===null)continue;
            $seen[hash('sha256',$line)]=true;$apps[$app]=true;
        }
        return ['events'=>count($seen),'applications'=>count($apps),'groups'=>array_keys($apps)];
    }
}
