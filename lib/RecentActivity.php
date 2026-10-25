<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Paid admission only; cold evidence is retained, never acknowledged here. */
final class RecentActivity
{
    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=25;}
    public static function cutoff(): int {return time()-Policy::number('ai_analysis_recent_minutes')*60;}
    public static function latest(array $row,?int $now=null): int
    {
        $now=$now??time();$latest=0;$ip=Safety::canonicalIp($row['ip']??'');
        foreach(DecisionProtection::lines($row) as $line){
            $t=BehaviorStore::eventTime($line)??0;
            if($ip&&Safety::sourceIp($line)===$ip&&$t<=$now+300)$latest=max($latest,$t);
        }
        return $latest;
    }
    public static function fresh(array $row): bool {return self::latest($row)>=self::cutoff();}
    public static function query($query,string $prefix='') {
        if(self::enabled())$query->where($prefix.'last_event_at','>=',date('Y-m-d H:i:s',self::cutoff()))
            ->where($prefix.'last_event_at','<=',date('Y-m-d H:i:s',time()+300));
        return $query;
    }
    public static function filterLines(array $lines): array {
        if(!self::enabled())return $lines;
        return array_values(array_filter($lines,fn($l)=>is_string($l)&&($t=BehaviorStore::eventTime($l))!==null
            &&$t>=self::cutoff()&&$t<=time()+300&&Safety::sourceIp($l)!==null));
    }
    public static function migrate(): void {
        if(!Capsule::schema()->hasColumn('mod_amssoft_fail2ban_rollups','last_event_at')){
            Capsule::schema()->table('mod_amssoft_fail2ban_rollups',function($t){$t->dateTime('last_event_at')->nullable()->index();});
        }
        if(!Capsule::schema()->hasColumn(EvidenceLinks::TABLE,'validation_context_hash'))
            Capsule::schema()->table(EvidenceLinks::TABLE,function($t){$t->char('validation_context_hash',64)->nullable();});
        foreach(['eligibility_reason','evidence_latest_at','policy_hash'] as $column)if(!Capsule::schema()->hasColumn(DecisionProtection::TABLE,$column))
            Capsule::schema()->table(DecisionProtection::TABLE,function($t)use($column){
                if($column==='evidence_latest_at')$t->dateTime($column)->nullable();
                else $t->string($column,$column==='policy_hash'?64:80)->nullable();
            });
        // Only metadata backfill. Existing attempt/revision/evidence fields stay untouched.
        Capsule::table('mod_amssoft_fail2ban_rollups')->whereNull('last_event_at')->orderBy('id')->chunk(200,function($rows){
            foreach($rows as $r){$t=self::latest((array)$r);if($t)Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$r->id)
                ->whereNull('last_event_at')->update(['last_event_at'=>date('Y-m-d H:i:s',$t)]);}
        });
    }
}
