<?php
namespace AMS\Fail2Ban;

/**
 * Exceção lançada quando a resposta da API de IA não contém JSON válido.
 * Diferente de TruncatedResponseException (resposta cortada por max_tokens),
 * esta indica que a resposta não é parseable como JSON array.
 */
class InvalidResponseException extends \RuntimeException {}
