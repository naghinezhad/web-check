<?php

function getCrawlRules($domain)
{
    $url = "http://$domain/robots.txt";
    $robotsTxt = @file_get_contents($url);

    if ($robotsTxt === false) {
        return ['error' => 'Unable to fetch robots.txt'];
    }

    return ['rules' => explode("\n", $robotsTxt)];
}
