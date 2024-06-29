<?php

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['domain'])) {
    $domain = filter_var($_POST['domain'], FILTER_SANITIZE_STRING);

    // Remove protocol (http:// or https://) and trailing slashes from the domain
    $domain = preg_replace('#^https?://#', '', rtrim($domain, '/'));

    // Get IP address
    include 'get_ip.php';
    $ip = getIpFromDomain($domain);

    // Get SSL Chain
    include 'get_ssl.php';
    $sslInfo = getSslChain($domain);

    // Get DNS Records
    include 'get_dns.php';
    $dnsRecords = getDnsRecords($domain);

    // Get Cookies
    include 'get_cookies.php';
    $cookies = getCookies($domain);

    // Get Crawl Rules
    include 'get_crawl_rules.php';
    $crawlRules = getCrawlRules($domain);

    // Get Headers
    include 'get_headers.php';
    $headers = getHeaders($domain);

    // Response
    $response = [
        'ip' => $ip,
        'ssl' => $sslInfo,
        'dns' => $dnsRecords,
        'cookies' => $cookies,
        'crawl_rules' => $crawlRules,
        'headers' => $headers,
    ];

    header('Content-Type: application/json');
    echo json_encode($response);
}
