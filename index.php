<?php

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['domain'])) {
    $domain = filter_var($_POST['domain'], FILTER_SANITIZE_STRING);

    $domain = preg_replace('#^https?://#', '', rtrim($domain, '/'));

    $route = './function/';

    // Get IP address
    include $route . '/get_ip.php';
    $ip = getIpFromDomain($domain);

    // Get SSL Chain
    include $route . 'get_ssl.php';
    $sslInfo = getSslChain($domain);

    // Get DNS Records
    include $route . 'get_dns.php';
    $dnsRecords = getDnsRecords($domain);

    // Get Cookies
    include $route . 'get_cookies.php';
    $cookies = getCookies($domain);

    // Get Crawl Rules
    include $route . 'get_crawl_rules.php';
    $crawlRules = getCrawlRules($domain);

    // Get Headers
    include $route . 'get_headers.php';
    $headers = getHeaders($domain);

    // Get Quality Metrics
    include $route . 'get_quality_metrics.php';
    $qualityMetrics = getQualityMetrics($domain);

    // Get Server Location
    include $route . 'get_server_location.php';
    $serverLocation = getServerLocation($ip);

    // Get Associated Hosts
    include $route . 'get_associated_hosts.php';
    $associatedHosts = getAssociatedHosts($domain);

    // Get Redirect Chain
    include $route . 'get_redirect_chain.php';
    $redirectChain = getRedirectChain($domain);

    // Get TXT Records
    include $route . 'get_txt_records.php';
    $txtRecords = getTxtRecords($domain);

    // Check Server Status
    include $route . 'check_server_status.php';
    $serverStatus = checkServerStatus($domain);

    // Check Open Ports
    include $route . 'check_open_ports.php';
    $openPorts = checkOpenPorts($ip);

    // Perform Traceroute
    include $route . 'traceroute.php';
    $traceroute = traceroute($domain);

    // Response
    $response = [
        'ip' => $ip,
        'ssl' => $sslInfo,
        'dns' => $dnsRecords,
        'cookies' => $cookies,
        'crawl_rules' => $crawlRules,
        'headers' => $headers,
        'quality_metrics' => $qualityMetrics,
        'server_location' => $serverLocation,
        'associated_hosts' => $associatedHosts,
        'redirect_chain' => $redirectChain,
        'txt_records' => $txtRecords,
        'server_status' => $serverStatus,
        'open_ports' => $openPorts,
        'traceroute' => $traceroute,
    ];

    header('Content-Type: application/json');
    echo json_encode($response);
}
