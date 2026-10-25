<?php
namespace AMS\Fail2Ban;

/** Shared policy for generated filters, evidence and firewall identifiers. */
final class Safety
{
    public static function canonicalIp(string $ip): ?string
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? inet_ntop(inet_pton($ip)) : null;
    }

    public static function filterName(string $name): string
    {
        $name = ltrim(preg_replace('/[^a-z0-9-]/', '', strtolower($name)), '-');
        $name = preg_replace('/-+/', '-', $name);
        while (str_starts_with($name, 'amsfb-')) {
            $name = substr($name, 6);
        }
        return substr(trim($name, '-'), 0, 50);
    }

    public static function actionName(string $jail): string
    {
        // f2b- + amsfb- + 16 hex characters = 26, below iptables' 29 limit.
        return 'amsfb-' . substr(hash('sha256', $jail), 0, 16);
    }

    public static function isWhitelisted(string $ip, array $entries): bool
    {
        if (in_array($ip, $entries, true)) return true;
        $packed = @inet_pton($ip);
        if ($packed === false) return false;
        foreach ($entries as $entry) {
            if (!str_contains($entry, '/')) {
                if (@inet_pton($entry) === $packed) return true;
                continue;
            }
            [$network, $prefix] = explode('/', $entry, 2);
            $base = @inet_pton($network);
            if ($base === false || strlen($base) !== strlen($packed) || !ctype_digit($prefix)) continue;
            $bits = (int)$prefix;
            if ($bits > strlen($base) * 8) continue;
            $bytes = intdiv($bits, 8);
            $remaining = $bits % 8;
            if (substr($base, 0, $bytes) === substr($packed, 0, $bytes)
                && (!$remaining || ((ord($base[$bytes]) ^ ord($packed[$bytes])) & (255 << (8 - $remaining))) === 0)) {
                return true;
            }
        }
        return false;
    }

    public static function canBan(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $packed = inet_pton($ip);
        if (strlen($packed) === 4) {
            return ord($packed[0]) !== 0 && ord($packed[0]) !== 127;
        }
        if ($packed === str_repeat("\0", 16) || $packed === str_repeat("\0", 15) . "\1") {
            return false;
        }
        if (substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            return self::canBan(inet_ntop(substr($packed, 12)));
        }
        return true;
    }

    /** Only the connection peer, never an IP supplied inside a URL/user-agent. */
    public static function sourceIp(string $line): ?string
    {
        if (preg_match('/^(\S+)\s+-\s+/', $line, $m)
            || preg_match('/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d\s+WHMCS login failed from\s+(\S+)\s+area=/', $line, $m)
            || preg_match('/^(?:\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d\S*|[A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?:\S+\s+)?sshd(?:\[\d+\])?:.*\sfrom\s+(\S+)\s+port\s+\d+(?:\s|$)/', $line, $m)) {
            $ip = trim($m[1], '[]');
            return self::canonicalIp($ip);
        }
        if (preg_match('/^(?:\[[^\]\r\n]*\]\s*)*?\[client ([^\]]+)\]/', $line, $m)) {
            $ip = trim($m[1], '[]');
            if (str_starts_with($m[1], '[') && filter_var($ip, FILTER_VALIDATE_IP) !== false) return self::canonicalIp($ip);
            $withoutPort = trim(preg_replace('/:\d+$/', '', $ip), '[]');
            if (filter_var($withoutPort, FILTER_VALIDATE_IP) !== false) return self::canonicalIp($withoutPort);
            if (filter_var($ip, FILTER_VALIDATE_IP) !== false) return self::canonicalIp($ip);
        }
        return null;
    }

    public static function evidence(array $lines, string $ip): array
    {
        $ip = self::canonicalIp($ip);
        if ($ip === null) return [];
        return array_values(array_filter($lines, static fn($line) =>
            is_string($line) && self::sourceIp($line) === $ip));
    }

    public static function bindSuggestions(array $suggestions, array $lines): array
    {
        $result = [];
        foreach ($suggestions as $suggestion) {
            if (!is_array($suggestion) || !self::canBan($suggestion['ip'] ?? '')) {
                continue;
            }
            $suggestion['ip'] = self::canonicalIp($suggestion['ip']);
            $evidence = self::evidence($lines, $suggestion['ip']);
            if (!$evidence) {
                continue;
            }
            $cited=$suggestion['evidence']??[];
            if(is_string($cited)) $cited=json_decode($cited,true)?:[];
            $matched=array_values(array_intersect($evidence,is_array($cited)?$cited:[]));
            $suggestion['_evidence_validated']=!empty($matched);
            // Legacy/manual suggestions without exact citations remain review
            // leads, never automatic authority.
            $suggestion['evidence'] = array_slice($matched?:$evidence, 0, 5);
            $suggestion['filter_name'] = self::filterName($suggestion['filter_name'] ?? '');
            $result[] = $suggestion;
        }
        return $result;
    }
}
