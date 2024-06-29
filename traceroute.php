<?php

function traceroute($domain)
{
    ini_set('max_execution_time', 300);

    exec("tracert $domain", $output, $return_var);

    if ($return_var !== 0) {
        return ['error' => 'Unable to perform traceroute'];
    }

    return ['traceroute' => $output];
}
