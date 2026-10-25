<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Presentation index only. Never used by protection, eligibility or paid admission. */
final class DashboardMetadata
{
    public const REVISION=1;
    public const TABLE='mod_amssoft_fail2ban_ai_suggestions';

    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=32;}

    public static function values(array $row,?int $now=null): array
    {
        $now=$now??time();$refresh=null;$peer=Safety::canonicalIp($row['ip']??'');
        foreach(DecisionProtection::lines($row) as $line){
            $at=BehaviorStore::eventTime($line);
            if($peer&&Safety::sourceIp($line)===$peer&&$at!==null&&$at>$now+300)
                $refresh=min($refresh??PHP_INT_MAX,$at-300);
        }
        return ['dashboard_latest'=>RecentActivity::latest($row,$now),
            'dashboard_peer'=>$peer??($row['ip']??''),
            'dashboard_vector'=>AIDashboard::vector($row)?1:0,
            'dashboard_learning'=>AIDashboard::learningGroup($row+['id'=>0],[]),
            'dashboard_refresh'=>$refresh,'dashboard_revision'=>self::REVISION];
    }

    public static function migrate(): void
    {
        $columns=['dashboard_latest','dashboard_peer','dashboard_vector','dashboard_learning','dashboard_refresh','dashboard_revision'];
        $missing=array_values(array_filter($columns,fn($c)=>!Capsule::schema()->hasColumn(self::TABLE,$c)));
        if($missing)Capsule::schema()->table(self::TABLE,function($t)use($missing){
            foreach($missing as $column)switch($column){
                case 'dashboard_latest': $t->unsignedBigInteger($column)->default(0);break;
                case 'dashboard_peer': $t->string($column,45)->default('');break;
                case 'dashboard_vector': $t->boolean($column)->default(false);break;
                case 'dashboard_learning': $t->string($column,16)->nullable();break;
                case 'dashboard_refresh': $t->unsignedBigInteger($column)->nullable();break;
                case 'dashboard_revision': $t->unsignedSmallInteger($column)->default(0);break;
            }
        });
        foreach(['amsfb_dashboard_observation'=>['classification','dashboard_latest','created_at','id'],
            'amsfb_dashboard_learning'=>['dashboard_learning','created_at','id']] as $name=>$fields)
            if(!Capsule::select('SHOW INDEX FROM '.self::TABLE.' WHERE Key_name = ?',[$name]))
                Capsule::schema()->table(self::TABLE,fn($t)=>$t->index($fields,$name));
        // Bounded metadata backfill, no evidence/status/decision/revision changes.
        Capsule::table(self::TABLE)->where('dashboard_revision','!=',self::REVISION)
            ->select(['id','ip','evidence','promotion_result'])->orderBy('id')->chunkById(100,function($rows){
                foreach($rows as $r)Capsule::table(self::TABLE)->where('id',$r->id)
                    ->where('dashboard_revision','!=',self::REVISION)->update(self::values((array)$r));
            });
    }

    /** Small cron-only catch-up for legacy writes and evidence crossing the future bound. */
    public static function refresh(): int
    {
        if(!self::enabled()||PHP_SAPI!=='cli')return 0;
        $db=Capsule::connection();$lock=(int)$db->selectOne("SELECT GET_LOCK('amsfb_cycle',0) AS acquired")->acquired===1;
        if(!$lock)return 0;
        try{
            $count=0;$now=time();
            $rows=Capsule::table(self::TABLE)->where(fn($q)=>$q->where('dashboard_revision','!=',self::REVISION)
                ->orWhere('dashboard_refresh','<=',$now))->orderBy('id')->limit(100)->get(['id','ip','evidence','promotion_result']);
            foreach($rows as $row)$count+=Capsule::table(self::TABLE)->where('id',$row->id)
                ->whereRaw('BINARY ip <=> BINARY ?',[$row->ip])->whereRaw('BINARY evidence <=> BINARY ?',[$row->evidence])
                ->whereRaw('BINARY promotion_result <=> BINARY ?',[$row->promotion_result])->update(self::values((array)$row,$now));
            return $count;
        }finally{$db->selectOne("SELECT RELEASE_LOCK('amsfb_cycle')");}
    }
}
