<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Physical identity is unique; each decision has its own validated association. */
final class EvidenceLinks
{
    public const TABLE='mod_amssoft_fail2ban_evidence_links';

    public static function enabled(): bool {return (int)Database::getConfig('schema_version','0')>=22;}

    public static function link(string $fingerprint,int $id,array $s,string $state='valid',string $origin='native'): void
    {
        $values=[
            'fingerprint'=>$fingerprint,'suggestion_id'=>$id,'validation_state'=>$state,
            'confidence'=>(int)($s['confidence']??0),'regex_sha256'=>$origin==='native'?hash('sha256',$s['failregex']??''):null,
            'validation_generation'=>$origin==='native'?AIAnalyzer::RECOVERY_GENERATION:($s['validation_generation']??null),
            'validated_at'=>$origin==='native'?date('Y-m-d H:i:s'):($s['validated_at']??null),
            'linked_at'=>date('Y-m-d H:i:s'),'origin'=>$origin,
        ];
        if(RecentActivity::enabled())$values['validation_context_hash']=$origin==='native'?DecisionEligibility::contextHash():null;
        Capsule::table(self::TABLE)->insertOrIgnore($values);
        if($origin==='native')Capsule::table(self::TABLE)->where('fingerprint',$fingerprint)->where('suggestion_id',$id)
            ->where('validation_state','!=','rejected')->update(array_intersect_key($values,array_flip(['validation_state','confidence','regex_sha256','validation_generation','validated_at','validation_context_hash'])));
    }

    /** EXISTS avoids multiplying campaign counts when several decisions cite one event. */
    public static function eligible($query,string $alias,int $confidence,?int $id=null,?array $statuses=null)
    {
        return $query->where($alias.'.validation_state','valid')->whereExists(function($q)use($alias,$confidence,$id,$statuses){
            $q->selectRaw('1')->from(self::TABLE.' as el')
                ->join('mod_amssoft_fail2ban_ai_suggestions as es','es.id','=','el.suggestion_id')
                ->whereColumn('el.fingerprint',$alias.'.fingerprint')->where('el.validation_state','valid')
                ->whereColumn('es.ip',$alias.'.ip')->whereColumn('es.source_log',$alias.'.source_log')
                ->where('es.classification','ban')->where('es.status','!=','rejected')
                ->where('es.confidence','>=',$confidence)->where('el.confidence','>=',$confidence);
            if($id!==null)$q->where('el.suggestion_id',$id);
            if($statuses!==null)$q->whereIn('es.status',$statuses);
        });
    }

    public static function migrate(): void
    {
        if(!Capsule::schema()->hasTable(self::TABLE))Capsule::schema()->create(self::TABLE,function($t){
            $t->charset='utf8mb4';$t->collation='utf8mb4_unicode_ci';
            $t->char('fingerprint',64);$t->unsignedBigInteger('suggestion_id')->index();
            $t->string('validation_state',16)->default('unknown')->index();$t->unsignedTinyInteger('confidence')->default(0);
            $t->char('regex_sha256',64)->nullable();$t->string('validation_generation',64)->nullable();
            $t->timestamp('validated_at')->nullable();$t->timestamp('linked_at')->useCurrent();
            $t->string('origin',24);$t->primary(['fingerprint','suggestion_id']);
        });
        $status=Capsule::selectOne("SHOW TABLE STATUS LIKE 'mod_amssoft_fail2ban_evidence_links'");
        if(($status->Collation??'')!=='utf8mb4_unicode_ci')Capsule::statement('ALTER TABLE mod_amssoft_fail2ban_evidence_links CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        Capsule::table('mod_amssoft_fail2ban_detections')->orderBy('fingerprint')->chunk(200,function($rows){
            foreach($rows as $d)self::link($d->fingerprint,(int)$d->suggestion_id,(array)$d,$d->validation_state,'legacy_current');
        });
        // Exact retained citations reconstruct relationships, not authority.
        Capsule::table('mod_amssoft_fail2ban_ai_suggestions')->where('classification','ban')->where('confidence','>=',90)->orderBy('id')->chunk(200,function($rows){
            foreach($rows as $s){
                $lines=Safety::evidence(json_decode($s->evidence??'[]',true)?:[],$s->ip);
                if(!$lines)continue;
                foreach(Capsule::table('mod_amssoft_fail2ban_detections')->where('ip',$s->ip)->where('source_log',$s->source_log)->whereIn('evidence',$lines)->get() as $d)
                    self::link($d->fingerprint,(int)$s->id,(array)$s,'unknown','legacy_inferred');
            }
        });
    }
}
