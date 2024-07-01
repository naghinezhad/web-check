<?php

require_once './function/domain_info.php';

use Functions\DomainInfo;

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['domain'])) {
    $domain = filter_var($_POST['domain'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $domain = preg_replace('#^https?://#', '', rtrim($domain, '/'));

    try {
        $domainInfo = new DomainInfo($domain);

        $response = [
            'ip' => $domainInfo->getIp(),
            'ssl' => $domainInfo->getSslChain(),
            'dns' => $domainInfo->getDnsRecords(),
            'cookies' => $domainInfo->getCookies(),
            'crawl_rules' => $domainInfo->getCrawlRules(),
            'headers' => $domainInfo->getHeaders(),
            'quality_metrics' => $domainInfo->getQualityMetrics(),
            'server_location' => $domainInfo->getServerLocation(),
            'associated_hosts' => $domainInfo->getAssociatedHosts(),
            'redirect_chain' => $domainInfo->getRedirectChain(),
            'txt_records' => $domainInfo->getTxtRecords(),
            'server_status' => $domainInfo->getServerStatus(),
            'open_ports' => $domainInfo->checkOpenPorts(),
            'traceroute' => $domainInfo->traceroute(),
            'carbon_footprint' => $domainInfo->getCarbonFootprint(),
            'server_info' => $domainInfo->getServerInfo(),
            'whois_lookup' => $domainInfo->getWhoisLookup(),
            'whois_info' => $domainInfo->getWhoisInfo(),
            'dns_sec' => $domainInfo->getDnsSec(),
            'site_features' => $domainInfo->getSiteFeatures(),
            'hsts' => $domainInfo->checkHSTS(),
            'dns_server' => $domainInfo->getDNSServer(),
            'tech_stack' => $domainInfo->getTechStack(),
            'listed_pages' => $domainInfo->getSitemap(),
            'security_txt' => $domainInfo->getSecurityTxt(),
            'linked_pages' => $domainInfo->getLinkedPages(),
            'social_tags' => $domainInfo->getSocialTags(),
            'email_config' => $domainInfo->getEmailConfig(),
            'firewall_detection' => $domainInfo->checkWAF(),
            'http_security_features' => $domainInfo->getSecurityHeaders(),
            'archive_history' => $domainInfo->getArchiveHistory(),
            'global_ranking' => $domainInfo->getGlobalRanking(),
            'block_detection' => $domainInfo->checkBlockStatus(),
            'malware_phishing_detection' => $domainInfo->detectMalwareAndPhishing(),
            'tls_cipher_suites' => $domainInfo->getTLSCipherSuites(),
            'tls_security_config' => $domainInfo->checkTLSSecurityConfig(),
            'tls_handshake_simulation' => $domainInfo->simulateTLSHandshake(),
            'screenshot' => $domainInfo->takeScreenshot(),
        ];

        header('Content-Type: application/json');
        echo json_encode($response);
    } catch (Exception $e) {
        header('Content-Type: application/json', true, 500);
        echo json_encode(['error' => $e->getMessage()]);
    }
} else {
    echo '
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Domain Info Test</title>
    </head>
    <body>
        <form method="POST" action="">
            <label for="domain">Domain:</label>
            <input type="text" id="domain" name="domain">
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>';
}
