<?php
namespace AMS\Fail2Ban;

final class Privileged
{
    public static function run(array $arguments): array
    {
        if(CycleBudget::active()) {
            $reads=['health','effective-config','tickets','check-ban','monitor-status','audit-snapshot','verify-archive','ai-jail-health','jail-filter-state','validate-filter','client-read','ban-coverage','prepare-evidence','filter-coverage','normalize-filter'];
            $reads[]='protection-snapshot';
            $reads[]='ips-snapshot';
            $reads[]='dashboard-protection-snapshot';
            if(in_array($arguments[0]??'', $reads,true))
                $arguments=array_merge(['--read-budget',(string)CycleBudget::timeout()],$arguments);
            else CycleBudget::requireTime(47); // helper alarm: 45 seconds, plus finalization margin
        }
        $command = '/usr/bin/sudo -n /usr/local/sbin/amsfb-admin '
            . implode(' ', array_map('escapeshellarg', $arguments)) . ' 2>&1';
        exec($command, $lines, $code);
        $result = json_decode(implode("\n", $lines), true);
        if(CycleBudget::active()&&($result['code']??'')==='cycle_budget')throw new CycleBudgetExceeded('Tempo de consulta/validação esgotado.');
        // Structured refusal is useful for validation diagnostics, not a success.
        return is_array($result) && ($code === 0 || empty($result['success'])) ? $result
            : ['success' => false, 'error' => 'Operação privilegiada recusada; verifique instalação e validação.'];
    }
}
