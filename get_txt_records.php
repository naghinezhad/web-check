<?php

function getTxtRecords($domain)
{
    $records = dns_get_record($domain, DNS_TXT);

    if (!$records) {
        return ['error' => 'No TXT records found'];
    }

    return ['txt_records' => $records];
}
