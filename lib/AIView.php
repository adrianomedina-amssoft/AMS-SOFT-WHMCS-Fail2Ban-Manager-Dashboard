<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Presentation only. Never seeds the worker projection or authorizes a ban. */
final class AIView
{
    private const TABLE='mod_amssoft_fail2ban_ai_suggestions';
    public static function input(array $input): array
    {
        $out=[];
        foreach(['pending_page','history_page','observations_page','learning_page'] as $key){
            $value=$input[$key]??'1';
            if(!is_string($value)||!preg_match('/^[1-9][0-9]{0,6}$/D',$value))throw new \InvalidArgumentException('Página inválida.');
            $out[$key]=(int)$value;
        }
        $choices=['decision_view'=>[DecisionProtection::VIEWS,'actionable'],
            'observation_scope'=>[AIDashboard::OBSERVATION_SCOPES,'all'],
            'learning_scope'=>[AIDashboard::LEARNING_SCOPES,'review'],
            'filter_status'=>[['','pending','approved','rejected','auto_executed'],''],
            'filter_severity'=>[['','low','medium','high','critical'],'']];
        foreach($choices as $key=>[$allowed,$default]){
            $value=$input[$key]??$default;
            if(!is_string($value)||!in_array($value,$allowed,true))throw new \InvalidArgumentException('Filtro inválido.');
            $out[$key]=$value;
        }
        foreach(['date_from','date_to'] as $key){
            $value=$input[$key]??'';
            if(!is_string($value)||($value!==''&&(!preg_match('/^([1-9][0-9]{3})-([0-9]{2})-([0-9]{2})$/D',$value,$m)||!checkdate((int)$m[2],(int)$m[3],(int)$m[1]))))throw new \InvalidArgumentException('Data inválida; use AAAA-MM-DD.');
            $out[$key]=$value;
        }
        if($out['date_from']!==''&&$out['date_to']!==''&&$out['date_from']>$out['date_to'])throw new \InvalidArgumentException('Data inicial posterior à final.');
        return $out;
    }
    public static function id($value): int
    {
        if(!is_string($value)||!preg_match('/^[1-9][0-9]{0,9}$/D',$value))throw new \InvalidArgumentException('ID inválido.');
        return (int)$value;
    }
    public static function ids($value): array
    {
        if(!is_string($value)||strlen($value)>3000)throw new \InvalidArgumentException('Seleção inválida.');
        $ids=json_decode($value);
        if(!is_array($ids)||!array_is_list($ids)||!$ids||count($ids)>200)throw new \InvalidArgumentException('Selecione de 1 a 200 decisões.');
        foreach($ids as $id)if(!is_int($id)||$id<=0||$id>9999999999)throw new \InvalidArgumentException('Seleção contém ID inválido.');
        return array_values(array_unique($ids));
    }
    public static function projection(): array
    {
        if(!DecisionProtection::enabled())throw new \RuntimeException('Schema sem projeção segura.');
        if(Capsule::table(self::TABLE)->where('status','pending')->where('classification','ban')->count()>5000)throw new \RuntimeException('Limite de apresentação excedido.');
        // Grouped native read, not one client process per jail.
        $snapshot=Privileged::run(['--read-budget','15','dashboard-protection-snapshot']);
        $snapshot['ttl']=Policy::number('ai_blocked_recheck_seconds');
        $projection=DecisionProtection::refresh($snapshot,false);
        // Refuse an expired successful observation instead of presenting stale actionable controls.
        if(($snapshot['success']??false)===true&&is_int($snapshot['observed_at']??null)&&$snapshot['observed_at']+$snapshot['ttl']<=time())throw new \RuntimeException('Consulta vencida.');
        return $projection;
    }
    private static function paged($q,int $page): array
    {
        $total=(int)(clone $q)->count();$pages=max(1,(int)ceil($total/10));$page=max(1,min($page,$pages));
        return ['data'=>$q->orderByDesc('created_at')->orderByDesc('id')->offset(($page-1)*10)->limit(10)->get()->map(fn($r)=>(array)$r)->all(),'total'=>$total,'pages'=>$pages,'page'=>$page];
    }
    public static function pending(array $projection,string $view,int $page): array
    {
        return self::paged(Capsule::table(self::TABLE)->where('status','pending')->where('classification','ban')->whereIn('id',$projection['groups'][$view]??[]),$page);
    }
    public static function history(array $filters,int $page): array
    {
        $q=Capsule::table(self::TABLE);
        foreach(['status','severity'] as $key)if(($filters[$key]??'')!=='')$q->where($key,$filters[$key]);
        if(($filters['date_from']??'')!=='')$q->where('created_at','>=',$filters['date_from'].' 00:00:00');
        if(($filters['date_to']??'')!=='')$q->where('created_at','<=',$filters['date_to'].' 23:59:59');
        return self::paged($q,$page);
    }
    private static function countryQuery(array $projection)
    {
        return Capsule::table(self::TABLE.' as s')->leftJoin('mod_amssoft_fail2ban_geo_cache as g',function($j){
            $j->on('s.ip','=','g.ip')->where('g.updated_at','>=',date('Y-m-d H:i:s',time()-30*86400));
        })->where('s.status','pending')->where('s.classification','ban')->whereIn('s.id',$projection['groups']['actionable']??[]);
    }
    public static function countries(array $projection): array
    {
        return self::countryQuery($projection)->selectRaw("COALESCE(g.country_code, '') as country_code, COALESCE(NULLIF(g.country, ''), 'Desconhecido') as country, COUNT(*) as ip_count")
            ->groupByRaw("COALESCE(g.country_code, ''), COALESCE(NULLIF(g.country, ''), 'Desconhecido')")->orderByDesc('ip_count')->orderBy('country_code')->get()->map(fn($r)=>(array)$r)->all();
    }
    public static function countryIds(string $country): array
    {
        if($country!==''&&!preg_match('/^[A-Z]{2}$/D',$country))throw new \InvalidArgumentException('País inválido.');
        $projection=Database::withPresentationConfigCache(fn()=>self::projection());
        $q=self::countryQuery($projection)->whereRaw("COALESCE(g.country_code, '') = ?",[$country]);
        $ids=$q->orderBy('s.id')->limit(201)->pluck('s.id')->map(fn($id)=>(int)$id)->all();
        return ['success'=>true,'ids'=>array_slice($ids,0,200),'limited'=>count($ids)>200,'count'=>min(200,count($ids))];
    }
    public static function proofCounts(array $rows): array
    {
        if(!$rows||!EvidenceLinks::enabled())return [];
        $out=[];
        foreach(Capsule::table(EvidenceLinks::TABLE)->whereIn('suggestion_id',array_column($rows,'id'))
            ->selectRaw('suggestion_id, validation_state, COUNT(*) as total')->groupBy('suggestion_id','validation_state')->get() as $r)$out[$r->suggestion_id][$r->validation_state]=(int)$r->total;
        return $out;
    }
}
