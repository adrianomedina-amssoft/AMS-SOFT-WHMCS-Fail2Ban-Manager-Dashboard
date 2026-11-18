<?php
namespace AMS\Fail2Ban;

/** Closed SQL syntax in the query, never a word in UA/referrer or a status. */
final class SqlInjection
{
    public static function queryPattern(): string
    {
        return '(?:'.self::legacyPattern().'|'.self::obfuscatedPattern().')';
    }
    /** Bounded executable-comment operators, never a keyword alone. Keep bridge parity. */
    public static function obfuscatedPattern(): string
    {
        $slash='(?:/|%2f|%252f)';$star='(?:\\*|%2a|%252a)';$bang='(?:!|%21|%2521)';
        $token=fn($word)=>$slash.$star.$bang.$word.$star.$slash;
        $n='[0-9]{1,12}';$eq='(?:=|%3d|%253d)';
        $lp='(?:\\(|%28|%2528)';$rp='(?:\\)|%29|%2529)';
        $q='(?:[\\x22\\x27]|%22|%27|%2522|%2527)';
        $predicate=$token('(?:and|or|where)').'(?:'.$token('not').')?'.$n
            .'(?:'.$eq.$n.'|'.$token('between').$n.$token('and').$n.')(?![0-9])';
        $value='(?:0x[0-9a-f]{1,32}|'.$n.'|'.$q.'[a-z0-9_]{1,80}'.$q.')';
        $conditional=$token('case').$token('when').$lp.$n.$eq.$n.$rp.$token('then').$value;
        return '(?:'.$predicate.'|'.$conditional.')';
    }
    public static function legacyPattern(): string
    {
        // Keep byte-for-byte parity with sql_query_pattern() in the bridge.
        $s='(?:[+ ]|%20|%2520){1,8}';$o='(?:[+ ]|%20|%2520){0,8}';
        $q='(?:[\x22\x27]|%22|%27|%2522|%2527)';
        $lp='(?:\(|%28|%2528)';$rp='(?:\)|%29|%2529)';
        $comma='(?:,|%2c|%252c)';$eq='(?:=|%3d|%253d)';$comment='(?:-|%2d|%252d){2}';
        $value='(?:null|[0-9]{1,12}|'.$q.'[a-z0-9_]{1,128}'.$q.')';
        $union='union'.$s.'(?:all'.$s.')?select'.$s.$value.'(?:'.$o.$comma.$o.$value.'){0,7}'.$o.$comment;
        $extract='(?:and'.$s.')?extractvalue'.$o.$lp.'[0-9]{1,12}'.$comma.$o.'concat'.$o.$lp.'0x[0-9a-f]{1,16}'.$comma.'[^"&#\r\n]{1,256}select'.$s.'[^"&#\r\n]{1,512}'.$comment;
        $order=$s.'order'.$s.'by'.$s.'[0-9]{1,6}'.$o.$comment;
        $boolean=$q.$rp.$s.'and'.$s.$lp.$q.'[a-z]{3,32}'.$q.$eq.$q.'[a-z]{3,32}'.$q.$q;
        return '(?:'.$union.'|'.$extract.'|'.$order.'|'.$boolean.')';
    }
    public static function target(string $target): bool
    {
        if(strlen($target)>8192||preg_match('/[\x00-\x1f\x7f]/',$target)||!str_starts_with($target,'/'))return false;
        $parts=explode('?',$target,2);
        return count($parts)===2&&preg_match('~'.self::queryPattern().'~iD',$parts[1])===1;
    }
    public static function fromLine(string $line): bool
    {
        return strlen($line)<=65536&&preg_match('~^\S+ - \S+ \[[^\]\r\n]*\] "[A-Z]{3,12} ([^ "\r\n]{1,8192}) HTTP/\d(?:\.\d)?" [1-5]\d\d (?:\d+|-)(?: |$)~D',$line,$m)
            &&self::target($m[1]);
    }
}
