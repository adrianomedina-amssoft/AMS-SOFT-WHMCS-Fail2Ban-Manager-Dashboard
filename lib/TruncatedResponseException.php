<?php
namespace AMS\Fail2Ban;

/**
 * Exceção lançada quando a resposta da API de IA é truncada por max_tokens.
 * Capturada pelo controller para sinalizar truncamento ao frontend.
 */
class TruncatedResponseException extends \RuntimeException {}
