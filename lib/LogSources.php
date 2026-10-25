<?php
namespace AMS\Fail2Ban;
/** Root bridge has the same immutable upper bound; UI may only select a subset. */
final class LogSources
{
    public const APPROVED=['/var/log/whmcs_auth.log','/var/log/apache2/error.log','/var/log/apache2/access.log',
        '/var/log/apache2/error_whmcs.log','/var/log/apache2/access_whmcs.log','/var/log/apache2/access_license_gateway.log',
        '/var/log/apache2/error_license_gateway.log','/var/log/auth.log'];
}
