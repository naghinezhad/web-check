<?php

function getCookies($domain)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://$domain");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('User-Agent: Mozilla/5.0'));

    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);

    curl_close($ch);

    preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header, $matches);
    $cookies = array();
    foreach ($matches[1] as $cookie) {
        parse_str($cookie, $cookie_arr);
        $cookies[] = $cookie_arr;
    }

    return $cookies;
}
