<?php
namespace AMS\Fail2Ban;
use WHMCS\Database\Capsule;

/** Read-only presentation. None of these heuristics grants blocking authority. */
final class AIDashboard
{
    public const OBSERVATION_SCOPES=['all','recent','history','review'];
    public const LEARNING_SCOPES=['all','pending','criteria','review','completed'];
    public static function vector(array $row): bool
    {
        foreach(DecisionProtection::lines($row) as $line){
            if(Safety::sourceIp($line)!==Safety::canonicalIp($row['ip']??''))continue;
            $target=RequestEvidence::target($line);if($target===null)continue;
            if(in_array(AttackFamily::fromLine($line),['sql-injection','path-traversal','command-injection'],true))return true;
            $path=explode('?',strtolower($target),2)[0];
            if(preg_match('~(?:^|/)\.env(?:$|[./])~',$path)&&!preg_match('~(?:^|/)\.env\.(?:example|sample|dist)(?:$|[./])~',$path))return true;
            if(preg_match('~(?:^|/)(?:\.git/(?:config|head|index|packed-refs)|\.svn/(?:entries|wc\.db)|wp-config\.php(?:\.(?:bak|old|save|swp))?|\.aws/(?:credentials|config)|\.docker/config\.json|\.ssh/(?:id_rsa|id_ed25519|config)|\.npmrc)(?:$|/)~',$path))return true;
        }
        return false;
    }
    public static function decisionStats(array $projection,array $rows): array
    {
        $out=[];$byId=[];$cutoff=RecentActivity::cutoff();foreach($rows as $r)$byId[(int)$r['id']]=$r;
        foreach($projection['groups'] as $view=>$ids){$ips=[];$recent=0;$undated=0;
            foreach($ids as $id){$r=$byId[$id]??null;if(!$r)continue;$ips[Safety::canonicalIp($r['ip'])??$r['ip']]=true;
                $latest=$projection['states'][$id]['eligibility']['latest']??RecentActivity::latest($r);
                if(!$latest)$undated++;elseif($latest>=$cutoff)$recent++;
            }
            $out[$view]=['records'=>count($ids),'ips'=>count($ips),'recent'=>$recent,'history'=>count($ids)-$recent-$undated,'undated'=>$undated];
        }
        return $out;
    }
    public static function observationStats(array $rows): array
    {
        $groups=array_fill_keys(self::OBSERVATION_SCOPES,[]);$ips=[];$undated=0;$cutoff=RecentActivity::cutoff();
        foreach($rows as $r){$id=(int)$r['id'];$groups['all'][]=$id;$ips[Safety::canonicalIp($r['ip'])??$r['ip']]=true;
            $latest=RecentActivity::latest($r);if(!$latest)$undated++;else $groups[$latest>=$cutoff?'recent':'history'][]=$id;
            if(self::vector($r))$groups['review'][]=$id;
        }
        return ['groups'=>$groups,'counts'=>array_map('count',$groups),'ips'=>count($ips),'undated'=>$undated];
    }
    public static function reasonStats(array $projection,array $rows): array
    {
        $out=[];$byId=[];$cutoff=RecentActivity::cutoff();foreach($rows as $r)$byId[(int)$r['id']]=$r;
        foreach($projection['groups'] as $view=>$ids){$reasons=[];
            foreach($ids as $id){$r=$byId[$id]??null;if(!$r)continue;$state=$projection['states'][$id]??[];
                $reason=$view==='protected'?'effective_coverage':($state['eligibility']['reason']??$state['reason']??'coverage_unavailable');
                if(!isset($reasons[$reason]))$reasons[$reason]=['reason'=>$reason,'records'=>0,'ips'=>[],'historical'=>0];
                $reasons[$reason]['records']++;$reasons[$reason]['ips'][$r['ip']]=true;
                $latest=$state['eligibility']['latest']??RecentActivity::latest($r);
                if($latest&&$latest<$cutoff)$reasons[$reason]['historical']++;
            }
            foreach($reasons as &$reason)$reason['ips']=count($reason['ips']);unset($reason);
            $out[$view]=array_values($reasons);
        }return $out;
    }
    public static function learningGroup(array $row,array $requests): ?string
    {
        if(isset($requests[$row['id']]))return 'pending';
        $result=$row['promotion_result']??[];if(is_string($result))$result=json_decode($result,true)?:[];
        // Persisted criteria insufficiency is not a technical failure.
        if(($result['learning_state']??'')==='review'&&($result['code']??'')==='promotion_threshold')return 'criteria';
        return in_array($result['learning_state']??'', ['pending','review','completed'],true)?$result['learning_state']:null;
    }
    public static function learningPage(array $rows,array $requests,string $scope,int $page,int $perPage=10): array
    {
        $counts=array_fill_keys(self::LEARNING_SCOPES,0);$selected=[];
        foreach($rows as $r){$group=self::learningGroup($r,$requests);if($group===null)continue;$counts['all']++;$counts[$group]++;
            if($scope!=='all'&&$scope!==$group)continue;
            $result=json_decode($r['promotion_result']??'{}',true)?:[];
            $selected[]=['id'=>(int)$r['id'],'ip'=>$r['ip'],'status'=>$r['status'],'learning_group'=>$group,
                'code'=>$requests[$r['id']]['last_code']??$result['code']??'promotion_queued','updated_at'=>$r['resolved_at']??$r['created_at'],
                'retry_at'=>$requests[$r['id']]['retry_at']??null,'evidence'=>DecisionProtection::lines($r)];
        }
        $total=count($selected);$pages=max(1,(int)ceil($total/$perPage));$page=min(max(1,$page),$pages);
        return ['data'=>array_slice($selected,($page-1)*$perPage,$perPage),'total'=>$total,'page'=>$page,'pages'=>$pages,'counts'=>$counts];
    }
    public static function read(array $projection,string $observationScope,int $observationPage,string $learningScope,int $learningPage): array
    {
        return Database::withPresentationConfigCache(fn()=>DashboardQuery::read($projection,$observationScope,$observationPage,$learningScope,$learningPage));
    }
}
