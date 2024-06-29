<?php

function checkServerStatus($domain)
{
    $ch = curl_init($domain);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); 
    curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($http_code === 200) {
        return ['status' => 'Server is online'];
    } else {
        return ['status' => 'Server is offline or not responding'];
    }

    curl_close($ch);
}
