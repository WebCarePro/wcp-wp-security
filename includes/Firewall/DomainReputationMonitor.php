<?php
namespace WcpScanner\Firewall;

use WcpScanner\System\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * DomainReputationMonitor
 *
 * Automated Blacklist & Domain Reputation Early-Warning Sentinel:
 * Routinely inspects DNSBL threat blacklists, SSL certificate lifespan & SAN coverage,
 * and email authentication hygiene (SPF/DMARC) to alert administrators
 * before sites are blocklisted by Google Safe Browsing, mail servers, or browsers.
 */
class DomainReputationMonitor {

    public const OPTION_REPORT  = 'wcpscan_domain_reputation_report';
    public const CRON_HOOK      = 'wcpscan_domain_reputation_daily_check';

    // Leading DNSBL blacklists to query against
    private const IP_DNSBLS = [
        'zen.spamhaus.org'        => 'Spamhaus Zen (Spam/Exploits/Direct Botnets)',
        'bl.spamcop.net'          => 'SpamCop Network Defense',
        'b.barracudacentral.org'  => 'Barracuda Reputation Network',
        'dnsbl.sorbs.net'         => 'SORBS Aggregate Blacklist',
    ];

    private const DOMAIN_DNSBLS = [
        'dbl.spamhaus.org'        => 'Spamhaus Domain Blocklist (DBL)',
        'multi.surbl.org'         => 'SURBL Multi Domain Threat Feed',
    ];

    /**
     * Initialize cron hooks.
     */
    public static function init() {
        add_action(self::CRON_HOOK, [__CLASS__, 'run_reputation_audit']);

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + DAY_IN_SECONDS, 'daily', self::CRON_HOOK);
        }
    }

    /**
     * Run full reputation, SSL, and DNSBL assessment.
     *
     * @param bool $force_refresh
     * @return array
     */
    public static function run_reputation_audit(bool $force_refresh = false): array {
        if (!$force_refresh) {
            $cached = get_option(self::OPTION_REPORT, null);
            if (is_array($cached) && !empty($cached['scanned_timestamp']) && (time() - $cached['scanned_timestamp']) < (12 * HOUR_IN_SECONDS)) {
                return $cached;
            }
        }

        $site_url = home_url('/');
        $parsed = wp_parse_url($site_url);
        $domain = $parsed['host'] ?? 'localhost';

        $resolved_ip = gethostbyname($domain);
        $is_local = ($resolved_ip === '127.0.0.1' || str_starts_with($resolved_ip, '172.') || str_starts_with($resolved_ip, '192.168.') || str_starts_with($resolved_ip, '10.'));

        $ssl_info    = self::check_ssl_certificate($domain);
        $dns_info    = self::check_dns_records($domain);
        $dnsbl_info  = self::check_dnsbl_status($domain, $resolved_ip, $is_local);

        $issues = [];
        $score = 100;

        // SSL deductions
        if ($ssl_info['status'] === 'expired') {
            $score -= 40;
            $issues[] = [
                'type'     => 'ssl_expired',
                'severity' => 'critical',
                'message'  => esc_html__('SSL Certificate has expired! Visitors will see browser security warning screens.', 'wcp-security-scanner'),
            ];
        } elseif ($ssl_info['status'] === 'expiring_soon') {
            $score -= 15;
            $issues[] = [
                'type'     => 'ssl_expiring',
                'severity' => 'warning',
                'message'  => sprintf(
                    /* translators: %d: days remaining */
                    esc_html__('SSL Certificate expires in %d days. Ensure automated renewal succeeds.', 'wcp-security-scanner'),
                    $ssl_info['days_remaining']
                ),
            ];
        }

        // DNSBL deductions
        if ($dnsbl_info['total_listed'] > 0) {
            $score -= (min(50, $dnsbl_info['total_listed'] * 25));
            $issues[] = [
                'type'     => 'dnsbl_listed',
                'severity' => 'critical',
                'message'  => sprintf(
                    /* translators: 1: number of listings, 2: comma-separated list names */
                    esc_html__('Site domain or server IP is listed on %1$d threat blocklist(s): %2$s.', 'wcp-security-scanner'),
                    $dnsbl_info['total_listed'],
                    implode(', ', $dnsbl_info['listed_names'])
                ),
            ];
        }

        // SPF / DMARC deductions
        if (!$dns_info['has_dmarc'] && !$is_local) {
            $score -= 10;
            $issues[] = [
                'type'     => 'missing_dmarc',
                'severity' => 'warning',
                'message'  => esc_html__('No DMARC record found for this domain. Attackers may spoof outbound emails from your domain.', 'wcp-security-scanner'),
            ];
        }

        $overall_status = 'clean';
        if ($score < 60) {
            $overall_status = 'critical';
        } elseif ($score < 90) {
            $overall_status = 'warning';
        }

        $report = [
            'success'           => true,
            'scanned_at'        => current_time('mysql'),
            'scanned_timestamp' => time(),
            'domain'            => $domain,
            'resolved_ip'       => $resolved_ip,
            'is_local_env'      => $is_local,
            'reputation_score'  => max(0, $score),
            'status'            => $overall_status,
            'issues'            => $issues,
            'ssl'               => $ssl_info,
            'dns'               => $dns_info,
            'dnsbl'             => $dnsbl_info,
        ];

        update_option(self::OPTION_REPORT, $report, false);

        if (count($issues) > 0) {
            AuditLogger::log(
                'domain_reputation_anomaly',
                sprintf('Domain reputation audit identified %d warning(s) for %s (Score: %d/100).', count($issues), $domain, $score)
            );
        }

        return $report;
    }

    /**
     * Inspect SSL/TLS certificate on port 443.
     *
     * @param string $domain
     * @return array
     */
    public static function check_ssl_certificate(string $domain): array {
        if ($domain === 'localhost' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return [
                'status'         => 'local_or_ip',
                'days_remaining' => 999,
                'issuer'         => 'Local Development',
                'subject'        => $domain,
                'valid_from'     => current_time('mysql'),
                'valid_to'       => current_time('mysql'),
                'sans'           => [$domain],
            ];
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'timeout'           => 6,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $client = @stream_socket_client('ssl://' . $domain . ':443', $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);

        if (!$client) {
            return [
                'status'         => 'unreachable',
                'days_remaining' => 0,
                'issuer'         => 'Unavailable',
                'subject'        => $domain,
                'valid_from'     => '',
                'valid_to'       => '',
                'sans'           => [],
            ];
        }

        $params = stream_context_get_params($client);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing network socket stream.
        fclose($client);

        $cert_resource = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert_resource) {
            return [
                'status'         => 'no_cert',
                'days_remaining' => 0,
                'issuer'         => 'None',
                'subject'        => $domain,
                'valid_from'     => '',
                'valid_to'       => '',
                'sans'           => [],
            ];
        }

        $cert = openssl_x509_parse($cert_resource);
        if (!$cert || !isset($cert['validTo_time_t'])) {
            return [
                'status'         => 'parse_failed',
                'days_remaining' => 0,
                'issuer'         => 'Unknown',
                'subject'        => $domain,
                'valid_from'     => '',
                'valid_to'       => '',
                'sans'           => [],
            ];
        }

        $now = time();
        $valid_to = $cert['validTo_time_t'];
        $days_left = (int) round(($valid_to - $now) / 86400);

        $status = 'healthy';
        if ($days_left <= 0) {
            $status = 'expired';
        } elseif ($days_left <= 21) {
            $status = 'expiring_soon';
        }

        $issuer_parts = $cert['issuer'] ?? [];
        $issuer_name = $issuer_parts['O'] ?? ($issuer_parts['CN'] ?? 'Unknown CA');

        $sans = [];
        if (!empty($cert['extensions']['subjectAltName'])) {
            $raw_sans = explode(',', $cert['extensions']['subjectAltName']);
            foreach ($raw_sans as $s) {
                $sans[] = trim(str_replace('DNS:', '', $s));
            }
        }

        return [
            'status'         => $status,
            'days_remaining' => max(0, $days_left),
            'issuer'         => sanitize_text_field($issuer_name),
            'subject'        => sanitize_text_field($cert['subject']['CN'] ?? $domain),
            'valid_from'     => gmdate('Y-m-d H:i:s', $cert['validFrom_time_t'] ?? $now),
            'valid_to'       => gmdate('Y-m-d H:i:s', $valid_to),
            'sans'           => $sans,
        ];
    }

    /**
     * Inspect DNS records for SPF, DMARC, and MX.
     *
     * @param string $domain
     * @return array
     */
    public static function check_dns_records(string $domain): array {
        if ($domain === 'localhost' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return [
                'has_spf'   => true,
                'spf_record'=> 'v=spf1 +ip4:127.0.0.1 ~all (Local)',
                'has_dmarc' => true,
                'dmarc_record'=> 'v=DMARC1; p=none (Local)',
                'has_mx'    => true,
            ];
        }

        $has_spf = false;
        $spf_record = '';
        $has_dmarc = false;
        $dmarc_record = '';
        $has_mx = false;

        // Query domain TXT records for SPF
        $txt_records = @dns_get_record($domain, DNS_TXT);
        if (is_array($txt_records)) {
            foreach ($txt_records as $rec) {
                $txt = $rec['txt'] ?? ($rec['entries'][0] ?? '');
                if (str_starts_with($txt, 'v=spf1')) {
                    $has_spf = true;
                    $spf_record = substr($txt, 0, 200);
                    break;
                }
            }
        }

        // Query _dmarc.domain TXT records for DMARC
        $dmarc_records = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
        if (is_array($dmarc_records)) {
            foreach ($dmarc_records as $rec) {
                $txt = $rec['txt'] ?? ($rec['entries'][0] ?? '');
                if (str_starts_with($txt, 'v=DMARC1')) {
                    $has_dmarc = true;
                    $dmarc_record = substr($txt, 0, 200);
                    break;
                }
            }
        }

        // Query MX records
        $mx_records = @dns_get_record($domain, DNS_MX);
        if (is_array($mx_records) && count($mx_records) > 0) {
            $has_mx = true;
        }

        return [
            'has_spf'      => $has_spf,
            'spf_record'   => $spf_record,
            'has_dmarc'    => $has_dmarc,
            'dmarc_record' => $dmarc_record,
            'has_mx'       => $has_mx,
        ];
    }

    /**
     * Check IP and Domain against prominent DNSBL blacklists.
     *
     * @param string $domain
     * @param string $ip
     * @param bool   $is_local
     * @return array
     */
    public static function check_dnsbl_status(string $domain, string $ip, bool $is_local): array {
        if ($is_local) {
            return [
                'total_checked' => 0,
                'total_listed'  => 0,
                'is_clean'      => true,
                'listed_names'  => [],
                'providers'     => [],
            ];
        }

        $providers = [];
        $listed_names = [];

        // Reverse IP for IPv4 DNSBL query (e.g. 1.2.3.4 -> 4.3.2.1.zen.spamhaus.org)
        $ip_parts = explode('.', $ip);
        $reverse_ip = (count($ip_parts) === 4) ? implode('.', array_reverse($ip_parts)) : '';

        // 1. IP-based DNSBLs
        if (!empty($reverse_ip)) {
            foreach (self::IP_DNSBLS as $host => $name) {
                $query = $reverse_ip . '.' . $host;
                $listed = false;
                $res = @gethostbyname($query);
                if ($res !== $query && str_starts_with($res, '127.0.0.')) {
                    $listed = true;
                    $listed_names[] = $name;
                }
                $providers[] = [
                    'type'     => 'ip',
                    'host'     => $host,
                    'name'     => $name,
                    'is_listed'=> $listed,
                    'response' => $listed ? $res : 'Clean',
                ];
            }
        }

        // 2. Domain-based DNSBLs
        foreach (self::DOMAIN_DNSBLS as $host => $name) {
            $query = $domain . '.' . $host;
            $listed = false;
            $res = @gethostbyname($query);
            if ($res !== $query && str_starts_with($res, '127.0.0.')) {
                $listed = true;
                $listed_names[] = $name;
            }
            $providers[] = [
                'type'     => 'domain',
                'host'     => $host,
                'name'     => $name,
                'is_listed'=> $listed,
                'response' => $listed ? $res : 'Clean',
            ];
        }

        $total_listed = count($listed_names);

        return [
            'total_checked' => count($providers),
            'total_listed'  => $total_listed,
            'is_clean'      => ($total_listed === 0),
            'listed_names'  => $listed_names,
            'providers'     => $providers,
        ];
    }
}
