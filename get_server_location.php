<?php

function getServerLocation($ip)
{
    $url = "https://ipinfo.io/$ip/json";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For demo purposes only, consider using proper certificate validation in production
    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        return ['error' => 'Unable to fetch server location: ' . curl_error($ch)];
    }

    curl_close($ch);

    $data = json_decode($response, true);

    if ($data === null) {
        return ['error' => 'Unable to decode server location response'];
    }

    return $data;
}
