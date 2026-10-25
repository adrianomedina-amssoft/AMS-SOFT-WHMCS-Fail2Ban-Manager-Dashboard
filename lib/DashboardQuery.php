<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** SQL presentation only. No provider, protection refresh, finalization or writes. */
final class DashboardQuery
{
    private const TABLE='mod_amssoft_fail2ban_ai_suggestions';
    private const PAGE=10;

    private static function page(int $total,int $requested): array
    {
        $pages=max(1,(int)ceil($total/self::PAGE));
        return ['total'=>$total,'page'=>min(max(1,$requested),$pages),'pages'=>$pages];
    }

    public static function read(array $projection,string $observationScope,int $observationPage,string $learningScope,int $learningPage): array
    {
        if(!in_array($observationScope,AIDashboard::OBSERVATION_SCOPES,true)
            ||!in_array($learningScope,AIDashboard::LEARNING_SCOPES,true))throw new \InvalidArgumentException('Categoria inválida.');
        $now=time();$cutoff=$now-Policy::number('ai_analysis_recent_minutes')*60;
        $requests=json_decode(Database::getConfig('ai_rule_requests','{}'),true)?:[];
        $indexed=DashboardMetadata::enabled()&&!Capsule::table(self::TABLE)
            ->where(fn($q)=>$q->where('dashboard_revision','!=',DashboardMetadata::REVISION)
                ->orWhere('dashboard_refresh','<=',$now))->exists();
        $pages=$indexed?self::indexed($requests,$cutoff,$observationScope,$observationPage,$learningScope,$learningPage)
            :self::streamed($requests,$cutoff,$now,$observationScope,$observationPage,$learningScope,$learningPage);
        // The live projection remains authoritative for decision categories.
        // Fetch only compact metadata for its IDs, never the entire history.
        $ids=[];foreach($projection['groups'] as $group)foreach($group as $id)$ids[(int)$id]=true;
        $rows=[];
        foreach(array_chunk(array_keys($ids),500) as $part){
            $query=Capsule::table(self::TABLE)->whereIn('id',$part);
            $fields=$indexed?['id','ip','dashboard_latest']:['id','ip','evidence'];
            foreach($query->get($fields) as $object){
                $r=(array)$object;$id=(int)$r['id'];
                if(!isset($projection['states'][$id]['eligibility']['latest']))
                    $projection['states'][$id]['eligibility']['latest']=$indexed?(int)$r['dashboard_latest']:RecentActivity::latest($r,$now);
                $rows[]=['id'=>$id,'ip'=>$r['ip']];
            }
        }
        return $pages+['decisions'=>AIDashboard::decisionStats($projection,$rows),
            'decision_reasons'=>AIDashboard::reasonStats($projection,$rows),'simulation'=>ProbeSimulation::read(),
            'queue'=>BehaviorStore::health(),'at'=>$now,'protection_at'=>$projection['observed_at'],
            'recent_minutes'=>Policy::number('ai_analysis_recent_minutes'),'read_mode'=>$indexed?'indexed':'streamed'];
    }

    private static function indexed(array $requests,int $cutoff,string $scope,int $page,string $learningScope,int $learningPage): array
    {
        $base=Capsule::table(self::TABLE)->whereIn('classification',['monitor','whitelist']);
        $r=(array)(clone $base)->selectRaw('COUNT(*) AS total, COUNT(DISTINCT BINARY dashboard_peer) AS ips,
            COALESCE(SUM(dashboard_latest >= ?),0) AS recent,
            COALESCE(SUM(dashboard_latest > 0 AND dashboard_latest < ?),0) AS history,
            COALESCE(SUM(dashboard_latest = 0),0) AS undated,
            COALESCE(SUM(dashboard_vector = 1),0) AS review',[$cutoff,$cutoff])->first();
        $stats=['counts'=>['all'=>(int)$r['total'],'recent'=>(int)$r['recent'],'history'=>(int)$r['history'],'review'=>(int)$r['review']],
            'ips'=>(int)$r['ips'],'undated'=>(int)$r['undated']];
        $observation=self::page($stats['counts'][$scope],$page);
        if($scope==='recent')$base->where('dashboard_latest','>=',$cutoff);
        elseif($scope==='history')$base->where('dashboard_latest','>',0)->where('dashboard_latest','<',$cutoff);
        elseif($scope==='review')$base->where('dashboard_vector',1);
        $observation['data']=(clone $base)->orderByDesc('created_at')->orderByDesc('id')
            ->offset(($observation['page']-1)*self::PAGE)->limit(self::PAGE)->get()->map(fn($r)=>(array)$r)->all();
        $pending=[];
        foreach($requests as $id=>$request)if($request!==null&&ctype_digit((string)$id)&&(int)$id>0
            &&(string)(int)$id===(string)$id)$pending[]=$id;
        $normal=Capsule::table(self::TABLE);if($pending)$normal->whereNotIn('id',$pending);
        $counts=array_fill_keys(AIDashboard::LEARNING_SCOPES,0);
        foreach((clone $normal)->whereIn('dashboard_learning',['criteria','pending','review','completed'])->select('dashboard_learning')->selectRaw('COUNT(*) AS total')->groupBy('dashboard_learning')->get() as $row)
            $counts[$row->dashboard_learning]=(int)$row->total;
        $counts['pending']+=$pending?(int)Capsule::table(self::TABLE)->whereIn('id',$pending)->count():0;
        $counts['all']=array_sum($counts);
        $learning=self::page($counts[$learningScope],$learningPage);
        $query=Capsule::table(self::TABLE);
        if($learningScope==='pending')$query->where(function($q)use($pending){
            $q->where('dashboard_learning','pending');if($pending)$q->orWhereIn('id',$pending);
        });
        elseif($learningScope==='all')$query->where(function($q)use($pending){
            $q->whereIn('dashboard_learning',['criteria','pending','review','completed']);if($pending)$q->orWhereIn('id',$pending);
        });
        else {$query->where('dashboard_learning',$learningScope);if($pending)$query->whereNotIn('id',$pending);}
        $selected=$query->orderByDesc('created_at')->orderByDesc('id')->offset(($learning['page']-1)*self::PAGE)
            ->limit(self::PAGE)->get()->map(fn($r)=>(array)$r)->all();
        $learning=['data'=>AIDashboard::learningPage($selected,$requests,$learningScope,1,self::PAGE)['data']]+$learning+['counts'=>$counts];
        return ['observations'=>$observation,'observation_stats'=>$stats,'learning'=>$learning];
    }

    /** Compatibility path for old/unindexed/future evidence; bounded batches, no GET writes. */
    private static function streamed(array $requests,int $cutoff,int $now,string $scope,int $page,string $learningScope,int $learningPage): array
    {
        $counts=array_fill_keys(AIDashboard::OBSERVATION_SCOPES,0);$learningCounts=array_fill_keys(AIDashboard::LEARNING_SCOPES,0);
        $ips=[];$undated=0;$observations=[];$observationTail=[];$selected=[];$learningTail=[];$seen=0;$learned=0;
        $before=null;
        do {
            $q=Capsule::table(self::TABLE)->select(['id','ip','classification','status','evidence','promotion_result','created_at','resolved_at'])
                ->orderByDesc('created_at')->orderByDesc('id')->limit(100);
            if($before)$q->where(fn($q)=>$q->where('created_at','<',$before['created_at'])
                ->orWhere(fn($q)=>$q->where('created_at',$before['created_at'])->where('id','<',$before['id'])));
            $batch=$q->get();
            foreach($batch as $object){
                $r=(array)$object;$before=$r;
                if(in_array($r['classification'],['monitor','whitelist'],true)){
                    $counts['all']++;$ips[Safety::canonicalIp($r['ip'])??$r['ip']]=true;$latest=RecentActivity::latest($r,$now);$vector=AIDashboard::vector($r);
                    if(!$latest)$undated++;else $counts[$latest>=$cutoff?'recent':'history']++;
                    if($vector)$counts['review']++;
                    if($scope==='all'||($scope==='review'&&$vector)||($latest&&$scope===($latest>=$cutoff?'recent':'history')))
                        self::retain($r,++$seen,$page,$observations,$observationTail);
                }
                $group=AIDashboard::learningGroup($r,$requests);if($group===null)continue;
                $learningCounts['all']++;$learningCounts[$group]++;
                if($learningScope==='all'||$learningScope===$group)self::retain($r,++$learned,$learningPage,$selected,$learningTail);
            }
        }while(count($batch)===100);
        $observation=self::page($seen,$page);$learning=self::page($learned,$learningPage);
        if($page>$observation['pages'])$observations=array_slice($observationTail,-($seen%self::PAGE?:self::PAGE));
        if($learningPage>$learning['pages'])$selected=array_slice($learningTail,-($learned%self::PAGE?:self::PAGE));
        $observation['data']=$observations?Capsule::table(self::TABLE)->whereIn('id',array_column($observations,'id'))
            ->orderByDesc('created_at')->orderByDesc('id')->limit(self::PAGE)->get()->map(fn($r)=>(array)$r)->all():[];
        $learning=['data'=>AIDashboard::learningPage($selected,$requests,$learningScope,1,self::PAGE)['data']]+$learning+['counts'=>$learningCounts];
        return ['observations'=>$observation,'observation_stats'=>['counts'=>$counts,'ips'=>count($ips),'undated'=>$undated],'learning'=>$learning];
    }

    private static function retain(array $r,int $seen,int $page,array &$selected,array &$tail): void
    {
        $offset=(max(1,$page)-1)*self::PAGE;
        if($seen>$offset&&$seen<=$offset+self::PAGE)$selected[]=$r;
        $tail[]=$r;if(count($tail)>self::PAGE)array_shift($tail);
    }
}
