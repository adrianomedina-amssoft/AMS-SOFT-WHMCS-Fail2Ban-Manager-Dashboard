<?php
namespace AMS\Fail2Ban;

/** Closed request-target signature; not status, UA, referrer or ban authority. */
final class PhpCgiProbe
{
    public static function pattern(): string
    {
        // Keep in parity with php_cgi_target_pattern() in the root helper.
        $flag='(?:-|%2d|%252d|%ad|%25ad|%c2%ad|%25c2%25ad|\xAD|\xC2\xAD)d';
        $separator='(?:\+|%20|%2520| ){1,8}';
        $equals='(?:=|%3d|%253d)';
        $colon='(?::|%3a|%253a)';$slash='(?:/|%2f|%252f)';
        $allow=$flag.$separator.'allow_url_include'.$equals.'(?:1|on|true)';
        $prepend=$flag.$separator.'auto_prepend_file'.$equals.'php'.$colon.$slash.$slash.'input';
        return '/[^ "?#\r\n]{0,8190}\?(?:'.$allow.$separator.$prepend.'|'.$prepend.$separator.$allow.')';
    }

    public static function target(string $target): bool
    {
        return strlen($target)<=8192&&!preg_match('/[\x00-\x1f\x7f]/',$target)
            &&preg_match('~\A'.self::pattern().'\z~iD',$target)===1;
    }

    public static function fromLine(string $line): bool
    {
        return strlen($line)<=65536&&preg_match('~^\S+ - \S+ \[[^\]\r\n]*\] "[A-Z]{3,12} ([^ "\r\n]+) HTTP/\d(?:\.\d)?" [1-5]\d\d (?:\d+|-)(?: |$)~D',$line,$m)
            &&self::target($m[1]);
    }
}
