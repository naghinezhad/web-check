<?php

function getAssociatedHosts($domain)
{
    $url = "https://api.hackertarget.com/hostsearch/?q=$domain";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        return ['error' => 'Unable to fetch associated hosts: ' . curl_error($ch)];
    }

    curl_close($ch);

    $hosts = explode("\n", $response);
    return $hosts;
}
