<?php

function getSslChain($domain)
{
    $streamContext = stream_context_create([
        "ssl" => [
            "capture_peer_cert_chain" => true,
        ],
    ]);

    $client = @stream_socket_client(
        "ssl://$domain:443",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $streamContext
    );

    if (!$client) {
        return ['error' => "Unable to connect: $errstr ($errno)"];
    }

    $params = stream_context_get_params($client);
    $chain = $params["options"]["ssl"]["peer_certificate_chain"];

    $certificates = [];
    foreach ($chain as $cert) {
        $certInfo = openssl_x509_parse($cert);
        $certificates[] = $certInfo;
    }

    return $certificates;
}
