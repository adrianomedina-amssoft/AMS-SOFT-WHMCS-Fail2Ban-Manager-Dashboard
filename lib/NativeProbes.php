<?php
namespace AMS\Fail2Ban;

/** Fixed native policy, independent of provider and analysis mode. */
final class NativeProbes
{
    public const DEFAULT_GROUPS=['env','git','svn','wpconfig','credentials','wordpress','cms','traversal','query_traversal','phpunit','debug','db_admin','exchange_probe','gpon_probe','webshell_probe','php_cgi_probe'];
    // Only select these when the named applications are absent on monitored sites.
    public const APPLICATION_TRAPS=[
        'vmware_probe'=>['/developmentserver/metadatauploader'],
        'druid_probe'=>['/druid/index.html'],
        'odoo_probe'=>['/web/database/list','/xmlrpc/2/common'],
        'cisco_vpn_probe'=>['/+CSCOE+/logon.html'],
        'sonicwall_probe'=>['/sonicui/7/sslvpn-portal/','/api/sonicos/auth','/api/sonicos/tfa'],
        'citrix_probe'=>['/vpn/pluginlist.xml','/logon/LogonPoint/tmindex.html','/vpn/js/rdx/core/lang/rdx_en.json.gz'],
        'ivanti_probe'=>['/dana-na/nc/nc_gina_ver.txt','/dana-cached/hc/HostCheckerInstaller.osx','/dana-na/auth/url_default/welcome.cgi'],
        'globalprotect_probe'=>['/global-protect/prelogin.esp','/ssl-vpn/prelogin.esp'],
        'rdweb_probe'=>['/RDWeb','/RDWeb/Pages/en-US/login.aspx'],
        'exchange_auth_probe'=>['/owa/auth/errorFE.aspx','/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application','/owa/auth/logon.aspx'],
    ];
    public const GROUPS=[...self::DEFAULT_GROUPS,'session_lfi_probe','vmware_probe','druid_probe','odoo_probe','cisco_vpn_probe','sonicwall_probe','citrix_probe',
        'ivanti_probe','globalprotect_probe','rdweb_probe','exchange_auth_probe'];
    public const KEYS=['native_probe_enabled','native_probe_groups','native_probe_maxretry','native_probe_findtime','native_probe_bantime'];
    public static function changed(array $old,array $next): bool {
        foreach(self::KEYS as $k)if(($old[$k]??null)!==($next[$k]??null))return true;
        return false;
    }
    public static function sync(array $values): bool {
        $payload=['enabled'=>(int)$values['native_probe_enabled'],'groups'=>preg_split('/\s+/',trim($values['native_probe_groups']),-1,PREG_SPLIT_NO_EMPTY),
            'maxretry'=>(int)$values['native_probe_maxretry'],'findtime'=>(int)$values['native_probe_findtime'],'bantime'=>(int)$values['native_probe_bantime'],
            'whitelist'=>AutoBanEngine::loadWhitelist()];
        $tmp=tempnam('/tmp','amsfb_probes_');if(!$tmp)return false;
        try{if(file_put_contents($tmp,json_encode($payload))===false)return false;
            return !empty(Privileged::run(['sync-sensitive-probes',$tmp])['success']);
        }finally{unlink($tmp);}
    }
}
