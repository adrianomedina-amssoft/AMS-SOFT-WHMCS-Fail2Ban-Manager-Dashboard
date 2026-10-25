<?php
// Compatibility entry point; all fixtures now use connection-local temporary tables.
if(PHP_SAPI!=='cli')exit(1);
$argv[1]=$argv[1]??dirname(__DIR__,4);
require __DIR__.'/settings_sql.php';
