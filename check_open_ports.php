<?php

function checkOpenPorts($ip)
{
    $ports = [80, 443, 21];

    $results = [];
    foreach ($ports as $port) {
        $connection = @fsockopen($ip, $port, $errno, $errstr, 1);
        if (is_resource($connection)) {
            $results[$port] = 'open';
            fclose($connection);
        } else {
            $results[$port] = 'closed';
        }
    }

    return $results;
}
