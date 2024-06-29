<?php

function getHeaders($domain)
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

    $headers = [];
    foreach (explode("\r\n", $header) as $line) {
        if (strpos($line, ':') !== false) {
            list($key, $value) = explode(': ', $line, 2);
            $headers[$key] = $value;
        }
    }

    return $headers;
}
