<?php
namespace AMS\Fail2Ban;

/** Scoped monotonic budget; never interrupts a privileged write in flight. */
final class CycleBudget
{
    private static ?float $deadline=null;
    private static int $providerReserve=47;
    private static ?\Closure $clock=null;

    private static function now(): float
    {
        return self::$clock ? (self::$clock)() : hrtime(true)/1e9;
    }

    public static function begin(float $seconds,int $providerReserve=47): void { self::$deadline=self::now()+$seconds;self::$providerReserve=$providerReserve; }
    public static function end(): void { self::$deadline=null;self::$providerReserve=47; }
    public static function providerReserve(): int { return self::$providerReserve; }
    public static function active(): bool { return self::$deadline!==null; }
    public static function remaining(): float { return self::$deadline===null ? INF : max(0,self::$deadline-self::now()); }
    public static function requireTime(float $reserve=2): void
    {
        if(self::remaining()<$reserve)throw new CycleBudgetExceeded('Orçamento do ciclo encerrado; tarefa preservada.');
    }
    public static function timeout(int $maximum=43,float $reserve=2): int
    {
        self::requireTime($reserve+1);
        return (int)min($maximum,floor(self::remaining()-$reserve));
    }
}
