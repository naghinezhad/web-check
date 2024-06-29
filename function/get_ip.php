<?php

function getIpFromDomain($domain)
{
    $ip = gethostbyname($domain);
    return $ip;
}
