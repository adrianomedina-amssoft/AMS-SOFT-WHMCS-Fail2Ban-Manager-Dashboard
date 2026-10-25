<?php
namespace AMS\Fail2Ban;

use WHMCS\Database\Capsule;

/** Presentation only; daemon tickets and historical module events are separate facts. */
final class IpBanView
{
    public static function select(array $native,array $query): array
    {
        $errors=[];$filter='';$jail='';$page=1;
        if(isset($query['ip'])){
            if(!is_string($query['ip'])||strlen($query['ip'])>50||!preg_match('/^[0-9a-fA-F.:]*$/D',trim($query['ip'])))$errors[]='Filtro de IP inválido. Use um IP ou trecho literal, sem CIDR.';
            else {$filter=strtolower(trim($query['ip']));$filter=Safety::canonicalIp($filter)??$filter;}
        }
        if(isset($query['jail'])&&$query['jail']!==''){
            if(!is_string($query['jail'])||($jail=Helper::sanitizeJail($query['jail']))==='')$errors[]='Filtro de jail inválido.';
        }
        if(isset($query['page'])){
            if(!is_scalar($query['page'])||!preg_match('/^[1-9][0-9]{0,8}$/D',(string)$query['page']))$errors[]='Página inválida; exibindo a primeira página.';
            else $page=(int)$query['page'];
        }
        $rows=[];$jails=array_keys($native['statuses']);sort($jails);
        foreach($native['statuses'] as $name=>$status)foreach($status['banned_ip_list']??[] as $ip){
            if($filter!==''&&!str_contains(strtolower($ip),$filter))continue;
            if($jail!==''&&$name!==$jail)continue;
            $rows[]=['ip'=>$ip,'jail'=>$name];
        }
        usort($rows,static function($a,$b){$aa=inet_pton($a['ip']);$bb=inet_pton($b['ip']);return (strlen($aa)<=>strlen($bb))?:strcmp($aa,$bb)?:strcmp($a['jail'],$b['jail']);});
        $total=count($rows);$unique=count(array_unique(array_column($rows,'ip')));$pages=max(1,(int)ceil($total/10));$page=min($page,$pages);
        return ['rows'=>array_slice($rows,($page-1)*10,10),'jails'=>$jails,'page'=>$page,'pages'=>$pages,
            'records'=>$total,'unique'=>$unique,'filters'=>['ip'=>$filter,'jail'=>$jail],'errors'=>$errors];
    }

    public static function read(array $vars,array $query,?array $native=null): array
    {
        return Database::withPresentationConfigCache(static function()use($vars,$query,$native){
            $native=$native??IpBanSnapshot::read();$out=self::select($native,$query)+['native'=>$native,'geo'=>[],'ban_ip'=>'','open_modal'=>false,'at'=>time()];
            if(is_string($query['ban_ip']??null))$out['ban_ip']=Safety::canonicalIp(trim($query['ban_ip']))??'';
            $out['open_modal']=$out['ban_ip']!==''&&is_scalar($query['open_modal']??null)&&in_array((string)$query['open_modal'],['1','true'],true)&&$native['complete'];
            $tickets=$native['identities']??[];
            if($out['rows']&&!$tickets)$out['errors'][]='Tickets temporais não confirmados. Desbanimento indisponível nesta leitura; atualize a página.';
            $historyFailed=false;
            foreach($out['rows'] as &$row){
                $row['ticket']=$tickets[$row['jail'].'|'.$row['ip']]??null;
                $row['preview']=$row['ticket']?IpBanActions::preview($row['ip'],$row['jail'],$row['ticket']):null;
                $row['history']=null;$row['history_known']=false;
                try{
                    $r=Capsule::table('mod_amssoft_fail2ban_logs')->where('ip',$row['ip'])->where('jail',$row['jail'])
                        ->whereIn('action',['ban','manual_ban'])->where('timestamp','<=',date('Y-m-d H:i:s'))
                        ->orderByDesc('timestamp')->orderByDesc('id')->first(['timestamp','reason']);
                    $row['history']=$r?(array)$r:null;$row['history_known']=true;
                }catch(\Throwable $e){$historyFailed=true;}
            }unset($row);
            if($historyFailed)$out['errors'][]='Histórico do módulo indisponível; os tickets nativos são exibidos separadamente.';
            try{$out['geo']=Database::getGeoCache(array_values(array_unique(array_column($out['rows'],'ip'))));}catch(\Throwable $e){}
            return $out;
        });
    }
}
