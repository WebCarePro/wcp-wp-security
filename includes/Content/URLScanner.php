<?php
namespace WCP\Scanner\Content;

if (!defined('ABSPATH')) {
    exit;
}

class URLScanner {

    private $site_host;

    public function __construct() {
        $home = get_option('home');
        $this->site_host = $home ? parse_url($home, PHP_URL_HOST) : null;
    }

    /**
     * Extract and analyze external URLs from text.
     *
     * @param string $content
     * @return array List of suspicious URL finding details
     */
    public function scan_urls($content) {
        $findings = [];

        if (empty($content) || !is_string($content)) {
            return $findings;
        }

        // Match all http/https URLs
        if (!preg_match_all('/https?:\/\/[^\s"\'<>]+/i', $content, $matches)) {
            return $findings;
        }

        $urls = array_unique($matches[0]);

        foreach ($urls as $url) {
            $parsed = parse_url($url);
            if (!isset($parsed['host'])) {
                continue;
            }

            $host = strtolower($parsed['host']);

            // Ignore local site domain
            if ($this->site_host && ($host === $this->site_host || substr($host, -(strlen($this->site_host) + 1)) === '.' . $this->site_host)) {
                continue;
            }

            // 1. Raw IP address in external URL
            if (preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $host)) {
                $findings[] = [
                    'url'        => $url,
                    'type'       => 'ip_based_external_url',
                    'desc'       => "Suspicious external URL using direct IP address: {$url}",
                    'severity'   => 'high',
                    'confidence' => 85
                ];
                continue;
            }

            // 2. High-risk or suspicious TLDs often abused in automated SEO injection
            $suspicious_tlds = ['top', 'work', 'xyz', 'click', 'buzz', 'fit', 'gq', 'ml', 'cf', 'tk'];
            $parts = explode('.', $host);
            $tld = end($parts);

            if (in_array($tld, $suspicious_tlds)) {
                // If it has excessive subdomains or query params
                if (count($parts) > 3 || isset($parsed['query'])) {
                    $findings[] = [
                        'url'        => $url,
                        'type'       => 'suspicious_tld_url',
                        'desc'       => "External link to domain with high-risk TLD (.{$tld}): {$url}",
                        'severity'   => 'medium',
                        'confidence' => 75
                    ];
                }
            }
        }

        return $findings;
    }
}
