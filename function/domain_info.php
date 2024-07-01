<?php

namespace Functions;

class DomainInfo
{
    private $domain;
    private $ip;

    public function __construct($domain)
    {
        $this->domain = $domain;
        $this->ip = gethostbyname($domain);
    }

    public function getIp()
    {
        return gethostbyname($this->domain);
    }

    public function getSslChain()
    {
        $streamContext = stream_context_create([
            "ssl" => [
                "capture_peer_cert_chain" => true,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$this->domain}:443",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $streamContext
        );

        if (!$client) {
            return $certificates = "Unable to connect: $errstr ($errno)";
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

    public function getDnsRecords()
    {
        $dnsRecords = @dns_get_record($this->domain, DNS_ALL);
        if ($dnsRecords === false) {
            return $dnsRecords =  "DNS Query failed";
        }
        return $dnsRecords;
    }

    public function getCookies()
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://{$this->domain}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('User-Agent: Mozilla/5.0'));

        $response = curl_exec($ch);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $header_size);

        curl_close($ch);

        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header, $matches);
        $cookies = array();
        foreach ($matches[1] as $cookie) {
            parse_str($cookie, $cookie_arr);
            $cookies[] = $cookie_arr;
        }

        return $cookies;
    }

    public function getCrawlRules()
    {
        $url = "http://{$this->domain}/robots.txt";
        $robotsTxt = @file_get_contents($url);

        if ($robotsTxt === false) {
            return $robotsTxt = "Unable to fetch robots.txt";
        }

        return ['rules' => explode("\n", $robotsTxt)];
    }

    public function getHeaders()
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://{$this->domain}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('User-Agent: Mozilla/5.0'));

        $response = curl_exec($ch);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $header_size);

        curl_close($ch);

        $headers = [];
        foreach (explode("\r\n", $header) as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(': ', $line, 2);
                $headers[$key] = $value;
            }
        }

        return $headers;
    }

    public function getQualityMetrics()
    {
        $lighthouseUrl = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=http://{$this->domain}";
        $response = file_get_contents($lighthouseUrl);
        $data = json_decode($response, true);

        if ($data === null || !isset($data['lighthouseResult'])) {
            return  $metrics = "Unable to fetch quality metrics";
        }

        $metrics = $data['lighthouseResult']['categories'];
        return $metrics;
    }

    public function getServerLocation()
    {
        $url = "https://ipinfo.io/{$this->ip}/json";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            return $data =  'Unable to fetch server location: ' . curl_error($ch);
        }

        curl_close($ch);

        $data = json_decode($response, true);

        if ($data === null) {
            return $data = 'Unable to decode server location response';
        }

        return $data;
    }

    public function getAssociatedHosts()
    {
        $url = "https://api.hackertarget.com/hostsearch/?q={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            return $hosts = 'Unable to fetch associated hosts: ' . curl_error($ch);
        }

        curl_close($ch);

        $hosts = explode("\n", $response);
        return $hosts;
    }

    public function getRedirectChain()
    {
        $domain = str_replace(['http://', 'https://'], '', $this->domain);
        $get = stream_context_create(array("ssl" => array("capture_peer_cert_chain" => true)));
        $read = @stream_socket_client("ssl://" . $domain . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

        if (!$read) {
            return $chain =  "Unable to connect: $errstr ($errno)";
        }

        $certChain = stream_context_get_params($read);
        $chain = [];
        foreach ($certChain['options']['ssl']['peer_certificate_chain'] as $cert) {
            $chain[] = openssl_x509_parse($cert);
        }
        return $chain;
    }

    public function getTxtRecords()
    {
        $records = dns_get_record($this->domain, DNS_TXT);

        if (!$records) {
            return $records =  'No TXT records found';
        }

        return ['txt_records' => $records];
    }

    public function getServerStatus()
    {
        $ch = curl_init($this->domain);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        if ($http_code === 200) {
            return ['status' => 'Server is online'];
        } else {
            return ['status' => 'Server might be offline'];
        }
    }

    public function checkOpenPorts()
    {
        $ports = [80, 443, 21, 22, 25, 110, 143];
        $results = [];

        foreach ($ports as $port) {
            $connection = @fsockopen($this->domain, $port, $errno, $errstr, 2);
            if (is_resource($connection)) {
                $results[$port] = 'open';
                fclose($connection);
            } else {
                $results[$port] = 'closed';
            }
        }
        return $results;
    }

    public function traceroute()
    {
        $output = shell_exec('traceroute ' . escapeshellarg($this->domain));
        return $output;
    }

    public function getCarbonFootprint()
    {
        $url = "https://api.websitecarbon.com/site?url={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return $data = "Unable to retrieve carbon footprint data.";
        }

        $data = json_decode($response, true);
        if (isset($data['error'])) {
            return $data = $data['error'];
        }

        return $data;
    }

    public function getServerInfo()
    {
        $url = "https://api.hackertarget.com/httpheaders/?q={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return $response =  "Unable to retrieve server info.";
        }

        return $response;
    }

    public function getWhoisLookup()
    {
        $url = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=your_api_key&domainName={$this->domain}&outputFormat=JSON";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return $data = "Unable to retrieve WHOIS data.";
        }

        $data = json_decode($response, true);
        if (isset($data['ErrorMessage'])) {
            return $data = $data['ErrorMessage'];
        }

        return $data;
    }

    public function getWhoisInfo()
    {
        $output = [];
        exec("whois {$this->domain}", $output);
        return implode("\n", $output);
    }

    public function getDnsSec()
    {
        $url = "https://dnssec-analyzer.verisignlabs.com/{$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return  $response = "Unable to retrieve DNSSEC data.";
        }

        return $response;
    }

    public function getSiteFeatures()
    {
        $url = "https://builtwith.com/{$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return  $response =  "Unable to retrieve site features data.";
        }

        return $response;
    }

    public function checkHSTS()
    {
        $headers = get_headers("https://{$this->domain}", 1);
        return isset($headers['Strict-Transport-Security']) ? $headers['Strict-Transport-Security'] : 'HSTS not enabled';
    }

    public function getDNSServer()
    {
        $dnsRecords = dns_get_record($this->domain, DNS_NS);
        return $dnsRecords ? $dnsRecords : 'No DNS servers found';
    }

    public function getTechStack()
    {
        $apiKey = 'YOUR_WAPPALYZER_API_KEY';
        $url = "https://api.wappalyzer.com/v2/lookup/?urls=https://{$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            "x-api-key: $apiKey"
        ));
        $response = curl_exec($ch);
        curl_close($ch);

        return $response ? json_decode($response, true) : 'Unable to fetch tech stack';
    }

    public function getSitemap()
    {
        $sitemapUrl = "https://{$this->domain}/sitemap.xml";
        $sitemap = @file_get_contents($sitemapUrl);
        return $sitemap ? $sitemap : 'No sitemap found';
    }

    public function getSecurityTxt()
    {
        $urls = [
            "https://{$this->domain}/.well-known/security.txt",
            "https://{$this->domain}/security.txt"
        ];

        foreach ($urls as $url) {
            $content = @file_get_contents($url);
            if ($content) {
                return $content;
            }
        }

        return 'No security.txt file found';
    }

    public function getLinkedPages()
    {
        $url = "https://{$this->domain}";
        $html = @file_get_contents($url);
        if ($html === false) {
            return 'Unable to fetch page';
        }

        $doc = new \DOMDocument();
        @$doc->loadHTML($html);
        $links = $doc->getElementsByTagName('a');

        $linkedPages = [];
        foreach ($links as $link) {
            $href = $link->getAttribute('href');
            if ($href) {
                $linkedPages[] = $href;
            }
        }

        return $linkedPages;
    }

    public function getSocialTags()
    {
        $url = "https://{$this->domain}";
        $html = @file_get_contents($url);
        if ($html === false) {
            return 'Unable to fetch page';
        }

        $doc = new \DOMDocument();
        @$doc->loadHTML($html);
        $metaTags = $doc->getElementsByTagName('meta');

        $socialTags = [];
        foreach ($metaTags as $metaTag) {
            if (
                $metaTag->getAttribute('property') === 'og:title' ||
                $metaTag->getAttribute('property') === 'og:description' ||
                $metaTag->getAttribute('property') === 'og:image'
            ) {
                $socialTags[$metaTag->getAttribute('property')] = $metaTag->getAttribute('content');
            }
        }

        return $socialTags;
    }

    public function getEmailConfig()
    {
        $dnsRecords = dns_get_record($this->domain, DNS_TXT);
        $emailConfig = [];

        foreach ($dnsRecords as $record) {
            if (strpos($record['txt'], 'v=DMARC') !== false) {
                $emailConfig['DMARC'] = $record['txt'];
            }
            if (strpos($record['txt'], 'v=spf') !== false) {
                $emailConfig['SPF'] = $record['txt'];
            }
            if (strpos($record['txt'], 'k=rsa') !== false) {
                $emailConfig['DKIM'] = $record['txt'];
            }
        }

        return $emailConfig;
    }

    public function checkWAF()
    {
        $headers = get_headers("https://{$this->domain}", 1);
        $wafHeaders = [
            'X-Sucuri-ID', 'X-Sucuri-Cache', 'CF-Ray', 'X-Cache', 'Server'
        ];

        $wafDetected = [];
        foreach ($wafHeaders as $header) {
            if (isset($headers[$header])) {
                $wafDetected[$header] = $headers[$header];
            }
        }

        return $wafDetected ? $wafDetected : 'No WAF detected';
    }

    public function getSecurityHeaders()
    {
        $headers = get_headers("https://{$this->domain}", 1);
        $securityHeaders = [
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'
        ];

        $detectedHeaders = [];
        foreach ($securityHeaders as $header) {
            if (isset($headers[$header])) {
                $detectedHeaders[$header] = $headers[$header];
            }
        }

        return $detectedHeaders;
    }

    public function getArchiveHistory()
    {
        $archiveUrl = "https://web.archive.org/web/*/{$this->domain}";
        return $archiveUrl;
    }

    public function getGlobalRanking()
    {
        $url = "https://tranco-list.eu/api/rank?domain={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        return $response ? json_decode($response, true) : 'Unable to fetch global ranking';
    }

    public function checkBlockStatus()
    {
        $dnsblLists = [
            'zen.spamhaus.org', 'b.barracudacentral.org',
            'bl.spamcop.net', 'dnsbl.sorbs.net', 'psbl.surriel.com'
        ];

        $blockStatus = [];
        foreach ($dnsblLists as $dnsbl) {
            $listed = checkdnsrr("{$this->domain}.{$dnsbl}", "A");
            $blockStatus[$dnsbl] = $listed ? 'Listed' : 'Not listed';
        }

        return $blockStatus;
    }

    public function detectMalwareAndPhishing()
    {
        $lists = [
            "https://urlhaus.abuse.ch/downloads/csv/",
            "https://data.phishtank.com/data/online-valid.csv"
        ];

        $results = [];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        foreach ($lists as $list) {
            curl_setopt($ch, CURLOPT_URL, $list);
            $content = curl_exec($ch);
            if ($content === false) {
                $results[] = "Failed to fetch data from " . $list . ": " . curl_error($ch);
                continue;
            }
            if (strpos($content, $this->domain) !== false) {
                $results[] = "Listed in " . $list;
            }
        }

        curl_close($ch);

        return $results ? $results : "No listings found.";
    }


    public function getTLSCipherSuites()
    {
        $output = [];
        exec("nmap --script ssl-enum-ciphers -p 443 {$this->domain}", $output);
        return implode("\n", $output);
    }

    public function checkTLSSecurityConfig()
    {
        $url = "https://tls-observatory.services.mozilla.com/api/v1/scan?target={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        return $response ? json_decode($response, true) : 'Unable to fetch TLS security config';
    }

    public function simulateTLSHandshake()
    {
        $url = "https://www.ssllabs.com/ssltest/analyze.html?d={$this->domain}";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        return $response ? json_decode($response, true) : 'Unable to simulate TLS handshake';
    }

    public function takeScreenshot()
    {
        $apiKey = 'YOUR_API_KEY';
        $url = "https://api.screenshotmachine.com?key={$apiKey}&url=https://{$this->domain}&dimension=1024x768";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $image = curl_exec($ch);
        curl_close($ch);

        $filename = 'screenshot.png';
        file_put_contents($filename, $image);
        return $filename;
    }
}
