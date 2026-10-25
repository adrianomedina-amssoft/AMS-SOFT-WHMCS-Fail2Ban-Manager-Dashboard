<?php
namespace AMS\Fail2Ban;

/** Known stale-form rejection; never exposes an unexpected exception to clients. */
final class PolicyConflict extends \InvalidArgumentException
{
}
