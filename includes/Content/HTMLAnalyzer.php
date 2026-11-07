<?php
namespace WcpScanner\Content;

if (!defined('ABSPATH')) {
    exit;
}

class HTMLAnalyzer {

    /**
     * Inspect HTML content for hidden spam, CSS cloaking tricks, and deceptive elements.
     *
     * @param string $html
     * @return array List of findings details ['type', 'snippet', 'desc', 'severity', 'confidence']
     */
    public function detect_hidden_elements($html) {
        $detections = [];

        if (empty($html) || !is_string($html)) {
            return $detections;
        }

        // 1. Off-screen positioning (e.g. left:-9999px or top:-10000px) concealing external anchor links
        // Exclude accessible skip links (e.g. href="#content") and ensure the style directly applies to the link or its immediate wrapper
        if (preg_match('/(?:<a\s+[^>]*style\s*=\s*["\'][^"\']*(?:left|top)\s*:\s*-\s*[0-9]{3,}(?:px|em)[^"\']*["\'][^>]*href\s*=\s*["\']https?:\/\/|<(?:div|p|span|li)[^>]*style\s*=\s*["\'][^"\']*(?:left|top)\s*:\s*-\s*[0-9]{3,}(?:px|em)[^"\']*["\'][^>]*>\s*<a\s+[^>]*href\s*=\s*["\']https?:\/\/)/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_offscreen_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Off-screen negative CSS positioning hiding external anchor links.',
                'severity'   => 'high',
                'confidence' => 90
            ];
        }

        // 2. Invisible text tricks: display:none, visibility:hidden, opacity:0, font-size:0 wrapping external links
        // Tightened to apply directly to the anchor or immediate container (<div ...><a ...) to prevent matching entire document
        if (preg_match('/(?:<a\s+[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em)?)[^"\']*["\'][^>]*href\s*=\s*["\']https?:\/\/|<(?:div|p|span|li)[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em)?)[^"\']*["\'][^>]*>\s*<a\s+[^>]*href\s*=\s*["\']https?:\/\/)/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_hidden_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Invisible CSS styles (display:none, opacity:0, font-size:0) concealing links.',
                'severity'   => 'high',
                'confidence' => 88
            ];
        }

        // 3. Hidden or zero-dimension iframes (exclude legitimate video/audio/map embeds)
        if (preg_match('/<iframe[^>]*(?:width\s*=\s*["\']?[01]["\']?|height\s*=\s*["\']?[01]["\']?|style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\'])[^>]*>/i', $html, $matches)) {
            $is_trusted_embed = (bool) preg_match('/src\s*=\s*["\']https?:\/\/(?:www\.)?(?:youtube\.com|youtube-nocookie\.com|player\.vimeo\.com|vimeo\.com|spotify\.com|soundcloud\.com|maps\.google\.com|google\.com\/maps)/i', $matches[0]);
            if (!$is_trusted_embed) {
                $detections[] = [
                    'type'       => 'hidden_iframe',
                    'snippet'    => substr($matches[0], 0, 150),
                    'desc'       => 'Concealed zero-dimension or hidden iframe element detected.',
                    'severity'   => 'critical',
                    'confidence' => 95
                ];
            }
        }

        // 4. Suspicious remote script injections in content
        if (preg_match('/<script\s+[^>]*src\s*=\s*["\'](https?:[^"\']+)["\'][^>]*>/i', $html, $matches)) {
            $src = $matches[1];
            // Whitelist common legitimate embed/library CDNs and reputable SaaS / e-commerce services
            $is_whitelisted_cdn = (bool) preg_match('/(youtube\.com|vimeo\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|platform\.twitter\.com|connect\.facebook\.net|googletagmanager\.com|google-analytics\.com|recaptcha\.net|google\.com\/recaptcha|stripe\.com|reviews\.io|ordertracker\.com|logwork\.com|trustpilot\.com|yotpo\.com|klaviyo\.com|privy\.com|elfsight\.com|judge\.me|ahrefs\.com)/i', $src);
            if (!$is_whitelisted_cdn) {
                $detections[] = [
                    'type'       => 'remote_script_injection',
                    'snippet'    => substr($matches[0], 0, 150),
                    'desc'       => 'Remote JavaScript injection detected within post content. This is a severe XSS risk.',
                    'severity'   => 'critical',
                    'confidence' => 98
                ];
            }
        }

        // 5. Meta refresh cloaked redirect in content
        if (preg_match('/<meta\s+[^>]*http-equiv\s*=\s*\\\\?["\']?refresh\\\\?["\']?[^>]*content\s*=\s*\\\\?["\']?[0-9]*\s*;\s*url\s*=\s*([^"\'\\\\>\s]+)/i', $html, $m_meta)) {
            $target_url = trim($m_meta[1]);
            $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
            $target_host = wp_parse_url($target_url, PHP_URL_HOST) ?: '';

            if (!empty($target_host) && $home_host && strtolower($target_host) !== strtolower($home_host) && !str_ends_with(strtolower($target_host), '.' . strtolower($home_host))) {
                $detections[] = [
                    'type'       => 'content_meta_refresh_redirect',
                    'snippet'    => substr($m_meta[0], 0, 150),
                    'desc'       => sprintf('Malicious meta refresh redirect detected in content targeting external host "%s". Visitors are hijacked immediately.', esc_html($target_host)),
                    'severity'   => 'critical',
                    'confidence' => 99,
                ];
            }
        }

        // 6. Base href tag hijacking
        if (preg_match('/<base\s+[^>]*href\s*=\s*\\\\?["\'](https?:\/\/[^"\'\\\\>\s]+)/i', $html, $m_base)) {
            $base_url = trim($m_base[1]);
            $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';
            $base_host = wp_parse_url($base_url, PHP_URL_HOST) ?: '';

            if (!empty($base_host) && $home_host && strtolower($base_host) !== strtolower($home_host) && !str_ends_with(strtolower($base_host), '.' . strtolower($home_host))) {
                $detections[] = [
                    'type'       => 'content_base_href_hijack',
                    'snippet'    => substr($m_base[0], 0, 150),
                    'desc'       => sprintf('Malicious <base href> tag detected targeting external host "%s". All relative links, scripts, and form submissions will be stolen.', esc_html($base_host)),
                    'severity'   => 'critical',
                    'confidence' => 98,
                ];
            }
        }

        // 7. Inline JavaScript redirect in content (<script>...window.location... or location.replace)
        if (preg_match_all('/<script\b[^>]*>(.*?)<\/script>/is', $html, $script_matches)) {
            $js_scanner = new \WcpScanner\Malware\JavaScriptSecurityScanner();
            foreach ($script_matches[1] as $idx => $script_body) {
                $script_body = trim($script_body);
                if (empty($script_body)) {
                    continue;
                }

                // Direct DOM redirect detection
                if (preg_match('/(?:window\.location(?:\.replace|\.href|\s*=)|location\.replace\s*\(|location\.href\s*=|document\.location\s*=)\s*[\'"`]?(https?:\/\/[^\s\'"`\);]+)/i', $script_body, $redir_m)) {
                    $dest_url = $redir_m[1];
                    $dest_host = wp_parse_url($dest_url, PHP_URL_HOST) ?: '';
                    $home_host = wp_parse_url(home_url(), PHP_URL_HOST) ?: '';

                    if ($dest_host && $home_host && strtolower($dest_host) !== strtolower($home_host) && !str_ends_with(strtolower($dest_host), '.' . strtolower($home_host))) {
                        $detections[] = [
                            'type'       => 'content_dom_redirect',
                            'snippet'    => substr($script_matches[0][$idx], 0, 160),
                            'desc'       => sprintf('Inline JavaScript redirect in content hijacking visitors to external host "%s".', esc_html($dest_host)),
                            'severity'   => 'critical',
                            'confidence' => 96,
                        ];
                        continue;
                    }
                }

                // Run full JS security scanner on inline content
                $js_hits = $js_scanner->scan_content($script_body, 'inline_content_script', 'content_scan');
                foreach ($js_hits as $hit) {
                    $detections[] = [
                        'type'       => 'content_malicious_inline_js',
                        'snippet'    => substr($hit->code_snippet ?? $script_matches[0][$idx], 0, 160),
                        'desc'       => $hit->description . ' (' . $hit->evidence . ')',
                        'severity'   => $hit->severity,
                        'confidence' => $hit->confidence,
                    ];
                }
            }
        }

        return $detections;
    }
}
