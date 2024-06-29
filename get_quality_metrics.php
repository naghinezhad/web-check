<?php

function getQualityMetrics($domain)
{
    $lighthouseUrl = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=http://$domain";
    $response = file_get_contents($lighthouseUrl);
    $data = json_decode($response, true);

    if ($data === null || !isset($data['lighthouseResult'])) {
        return ['error' => 'Unable to fetch quality metrics'];
    }

    $metrics = $data['lighthouseResult']['categories'];
    return $metrics;
}
