<?php

function getRedirectChain($domain)
{
    $domain = str_replace(['http://', 'https://'], '', $domain);
    $get = stream_context_create(array("ssl" => array("capture_peer_cert_chain" => true)));
    $read = @stream_socket_client("ssl://" . $domain . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

    if (!$read) {
        return ['error' => "Unable to connect: $errstr ($errno)"];
    }

    $certChain = stream_context_get_params($read);
    $chain = [];
    foreach ($certChain['options']['ssl']['peer_certificate_chain'] as $cert) {
        $chain[] = openssl_x509_parse($cert);
    }
    return $chain;
}
