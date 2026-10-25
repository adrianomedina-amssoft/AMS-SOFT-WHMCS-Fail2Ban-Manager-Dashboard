<?php
namespace AMS\Fail2Ban;

/** Closed public vocabulary. Never interpolate provider, SQL or helper errors. */
final class ProtectionFailure extends \RuntimeException
{
    private const MESSAGES=[
        'policy_busy'=>'Configuração em uso; tente novamente',
        'api_key_required'=>'Configure uma chave API válida antes de ativar',
        'whitelist_unconfirmed'=>'Whitelist nativa não confirmada; configuração não alterada.',
        'jail_unconfirmed'=>'Jail da IA não confirmada; configuração não salva. Se há bans ativos, preserve a duração atual e confira o diagnóstico nativo.',
        'probes_unconfirmed'=>'Política nativa não confirmada; configuração não salva.',
        'routes_unconfirmed'=>'Catálogo nativo de rotas não confirmado; configuração não salva.',
        'native_reconciliation'=>'Configuração não salva; reconciliação nativa pendente. Verifique o módulo.',
        'routes_reconciliation'=>'Configuração não salva; reconciliação do catálogo nativo pendente.',
        'probes_reconciliation'=>'Reconciliação da sondagem nativa pendente.',
        'retry_not_allowed'=>'Trabalho não retomável por este autor.',
        'retry_policy_changed'=>'Política alterada; gere nova prévia.',
        'retry_backup_incomplete'=>'Backup inicial incompleto; gere nova prévia antes de continuar.',
        'retry_archive_unverified'=>'Integridade do arquivo não confirmada; retomada recusada.',
    ];

    public function __construct(public readonly string $reason,?\Throwable $previous=null)
    {
        if(!isset(self::MESSAGES[$reason]))throw new \LogicException('Motivo operacional desconhecido.');
        parent::__construct(self::MESSAGES[$reason],0,$previous);
    }
}
