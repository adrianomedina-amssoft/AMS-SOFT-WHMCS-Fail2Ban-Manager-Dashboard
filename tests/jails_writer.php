<?php
namespace AMS\Fail2Ban {
    class LogLock {public static function acquire($key){return ['fp'=>tmpfile()];}public static function release($fp){fclose($fp);}}
    class Privileged {public static function run($args){throw new \RuntimeException('No native calls permitted');}}
}
namespace {
    if(PHP_SAPI!=='cli')exit(1);
    require dirname(__DIR__).'/lib/Router.php';
    use AMS\Fail2Ban\JailConfig;
    $checks=0;function w42($v,$why){global $checks;if(!$v)throw new RuntimeException($why);$checks++;}
    $file=tempnam(sys_get_temp_dir(),'amsfb-test-jails-');
    try {
        $original="[DEFAULT]\nignoreip = 127.0.0.1\n\n[amsfb-example]\nenabled = true\nbantime = 48h\nfindtime = 10m\nmaxretry = 3\naction = custom-action[name=existing]\nlogpath = /var/log/a\n          /var/log/b\n";
        file_put_contents($file,$original);$c=new JailConfig($file);
        w42($c->readJailLocal()['amsfb-example']['logpath']==="/var/log/a\n/var/log/b",'Read multiline');
        $c->guardUiWrite($c->localHash());w42($c->saveJail('amsfb-example',['maxretry'=>'5']),'UI guarded write');
        $after=$c->readJailLocal();w42($after['amsfb-example']['action']==='custom-action[name=existing]','Preserve existing firewall action');
        w42($after['amsfb-example']['bantime']==='48h'&&$after['amsfb-example']['findtime']==='10m','Preserve native durations');
        w42($after['amsfb-example']['logpath']==="/var/log/a\n/var/log/b",'Preserve multiline through actual writer');
        w42($after['DEFAULT']['ignoreip']==='127.0.0.1','DEFAULT unchanged');
        $unchanged=file_get_contents($file);w42(!$c->saveJail('amsfb-example',['enabled'=>'false'])&&file_get_contents($file)===$unchanged,'Old optimistic hash refuses second write');
        $c=new JailConfig($file);$c->guardUiWrite($c->localHash());
        w42($c->addJail('amsfb-new',['enabled'=>'false']),'New jail allowed');
        w42(str_starts_with($c->readJailLocal()['amsfb-new']['action'],'iptables-multiport[name=amsfb-'),'New jail still gets safe action');
        w42(!$c->appliesOnWrite(),'Local fixture is not native install');
        $c=new JailConfig('/nonexistent/amsfb-audit-fixture');
        try{$c->localHash();w42(false,'Missing file must throw');}catch(RuntimeException $e){w42(true,'Missing file not empty config');}
    } finally {
        foreach(glob($file.'.bak.*')?:[] as $backup)unlink($backup);
        if(is_file($file))unlink($file);
    }
    echo "PASS: {$checks} actual JailConfig writer checks; temporary fixtures only\n";
}
