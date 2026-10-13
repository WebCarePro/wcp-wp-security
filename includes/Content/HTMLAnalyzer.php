<?php
namespace WCP\Scanner\Content;

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
            // Whitelist common legitimate embed/library CDNs
            $is_whitelisted_cdn = (bool) preg_match('/(youtube\.com|vimeo\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|platform\.twitter\.com|connect\.facebook\.net|googletagmanager\.com|google-analytics\.com|recaptcha\.net|google\.com\/recaptcha|stripe\.com)/i', $src);
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

        return $detections;
    }
}
