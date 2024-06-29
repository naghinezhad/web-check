<?php

function getDnsRecords($domain)
{
    $dnsRecords = @dns_get_record($domain, DNS_ALL);
    if ($dnsRecords === false) {
        return ['error' => "DNS Query failed"];
    }
    return $dnsRecords;
}
