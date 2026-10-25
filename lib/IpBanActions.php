<?php
namespace AMS\Fail2Ban;

/** Explicit administrative actions only; never invoked by a GET or the AI worker. */
final class IpBanActions
{
    public static function preview(string $ip,string $jail,string $ticket,?int $now=null): string
    {
        if(!isset($_SESSION['amsfb_ips_preview_key']))$_SESSION['amsfb_ips_preview_key']=bin2hex(random_bytes(32));
        $body=base64_encode(json_encode(['ip'=>$ip,'jail'=>$jail,'ticket'=>$ticket,'at'=>$now??time()],JSON_THROW_ON_ERROR));
        return $body.'.'.hash_hmac('sha256',$body,$_SESSION['amsfb_ips_preview_key']);
    }

    public static function ticket(string $token,string $ip,string $jail,?int $now=null): ?string
    {
        if(strlen($token)>2048||!isset($_SESSION['amsfb_ips_preview_key']))return null;
        $parts=explode('.',$token);if(count($parts)!==2||!hash_equals(hash_hmac('sha256',$parts[0],$_SESSION['amsfb_ips_preview_key']),$parts[1]))return null;
        $decoded=base64_decode($parts[0],true);if($decoded===false)return null;
        $data=json_decode($decoded,true);$now=$now??time();
        if(!is_array($data)||($data['ip']??null)!==$ip||($data['jail']??null)!==$jail||!is_int($data['at']??null)
            ||$data['at']>$now||$now-$data['at']>=900||!is_string($data['ticket']??null)
            ||$data['ticket']===''||strlen($data['ticket'])>200||preg_match('/[\r\n\x00]/',$data['ticket']))return null;
        return $data['ticket'];
    }

    private static function status(string $jail): array
    {
        $r=Privileged::run(['--read-budget','3','client-read','status',$jail]);
        if(($r['success']??false)!==true||!is_string($r['output']??null))throw new \RuntimeException('Native status unavailable');
        return DashboardOverview::jailStatus($r['output'])['banned_ip_list'];
    }

    private static function error(string $message,string $state='refused'): array
    { return ['success'=>false,'error'=>$message,'state'=>$state,'audit_recorded'=>false]; }

    private static function recorded(string $ip,string $jail,string $action,string $message): array
    {
        try {Database::logEvent($ip,$jail,$action,'Manual via WHMCS; estado confirmado na jail selecionada.',Helper::adminId());}
        catch(\Throwable $e){
            error_log('[AMSFB] IP action confirmed but audit persistence failed: '.get_class($e));
            return ['success'=>true,'warning'=>true,'state'=>'confirmed_audit_failed','audit_recorded'=>false,
                'message'=>$message.' Atenção: a alteração foi confirmada, mas o registro de auditoria falhou. Não repita a ação; confira os logs.'];
        }
        return ['success'=>true,'state'=>'confirmed','audit_recorded'=>true,'message'=>$message];
    }

    public static function execute(string $operation,array $post,Fail2BanClient $client): array
    {
        if(Helper::adminId()<=0||($_SERVER['REQUEST_METHOD']??'GET')!=='POST')return self::error('Operação exige sessão administrativa e POST.');
        if(!is_string($post['csrf_token']??null)||!Helper::checkCsrf($post['csrf_token']))return self::error('Token CSRF inválido.');
        if(!in_array($operation,['ban','unban'],true))return self::error('Ação desconhecida.');
        if(!is_string($post['ip']??null)||!is_string($post['jail']??null))return self::error('IP ou jail inválido.');
        $ip=Safety::canonicalIp(trim($post['ip']));$jail=Helper::sanitizeJail($post['jail']);
        if($ip===null||$jail==='')return self::error('IP ou jail inválido.');
        $identity=null;
        if($operation==='unban'){
            $identity=is_string($post['preview']??null)?self::ticket($post['preview'],$ip,$jail):null;
            if($identity===null)return self::error('Confirmação do ticket ausente, alterada ou vencida. Recarregue a lista antes de desbanir.','stale_preview');
        }
        try {
            $before=self::status($jail);
            if($operation==='ban'){
                if(in_array($ip,$before,true))return ['success'=>true,'warning'=>true,'state'=>'already_present','audit_recorded'=>false,
                    'message'=>"Já existe ticket de {$ip} em {$jail}; nenhum ban foi renovado. Confira a cobertura em Proteção."];
                if(!$client->banIP($jail,$ip))return self::error('Ban não confirmado. Pode haver recusa de segurança ou falha de aplicação; atualize e confira Proteção antes de repetir.','unconfirmed');
                if(!in_array($ip,self::status($jail),true))return self::error('Comando aceito, mas ticket atual não confirmado. Atualize antes de repetir.','unconfirmed');
                return self::recorded($ip,$jail,'manual_ban',"Ban de {$ip} confirmado na jail {$jail}.");
            }
            if(!in_array($ip,$before,true))return ['success'=>true,'warning'=>true,'state'=>'already_absent','audit_recorded'=>false,
                'message'=>"Nenhum ticket de {$ip} em {$jail} nesta consulta; nenhuma remoção executada. Outras jails não foram alteradas."];
            $result=Privileged::run(['unban-ticket',$jail,$ip,$identity]);
            if(($result['success']??false)!==true||!is_bool($result['skipped']??null))return self::error('Desbanimento não confirmado. Atualize a lista antes de repetir.','unconfirmed');
            $present=true;
            for($i=0;$i<4;$i++){
                $present=in_array($ip,self::status($jail),true);
                if(!$present||!empty($result['skipped']))break;
                usleep(100000);
            }
            if($present)return self::error(!empty($result['skipped'])?'O ticket mudou desde a consulta. O novo bloqueio não foi removido por esta ação. Recarregue a lista.':'Ticket ainda presente ou renovado. Desbanimento não confirmado; recarregue a lista.','changed_or_present');
            if(($result['skipped']??null)!==false)return ['success'=>true,'warning'=>true,'state'=>'already_absent','audit_recorded'=>false,
                'message'=>'O ticket original expirou ou mudou; nenhuma remoção confirmada por esta ação. Outras jails não foram alteradas.'];
            return self::recorded($ip,$jail,'manual_unban',"Ticket de {$ip} removido da jail {$jail}. Outras jails permanecem independentes; isso não cria whitelist nem comprova liberação global no firewall.");
        }catch(\Throwable $e){
            return self::error('Consulta ou resultado indisponível. Não foi possível confirmar a operação; atualize a lista e confira Proteção antes de repetir.','unconfirmed');
        }
    }
}
