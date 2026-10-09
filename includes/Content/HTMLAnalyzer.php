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

        // 1. Off-screen positioning (e.g. left:-9999px or top:-10000px) containing links
        if (preg_match('/style\s*=\s*["\'][^"\']*(?:left|top)\s*:\s*-\s*[0-9]{3,}(?:px|em)[^"\']*["\'][\s\S]*?<a\s+/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_offscreen_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Off-screen negative CSS positioning hiding external anchor links.',
                'severity'   => 'high',
                'confidence' => 90
            ];
        }

        // 2. Invisible text tricks: display:none, visibility:hidden, opacity:0, font-size:0 wrapping links
        if (preg_match('/style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em)?)[^"\']*["\'][\s\S]*?<a\s+/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'css_hidden_links',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Invisible CSS styles (display:none, opacity:0, font-size:0) concealing links.',
                'severity'   => 'high',
                'confidence' => 88
            ];
        }

        // 3. Hidden or zero-dimension iframes
        if (preg_match('/<iframe[^>]*(?:width\s*=\s*["\']?[01]["\']?|height\s*=\s*["\']?[01]["\']?|style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\'])[^>]*>/i', $html, $matches)) {
            $detections[] = [
                'type'       => 'hidden_iframe',
                'snippet'    => substr($matches[0], 0, 150),
                'desc'       => 'Concealed zero-dimension or hidden iframe element detected.',
                'severity'   => 'critical',
                'confidence' => 95
            ];
        }

        // 4. Suspicious remote script injections in content
        // Normally, posts should NOT contain script source tags (filtered by KSES unless DB compromised directly)
        if (preg_match('/<script\s+[^>]*src\s*=\s*["\'](http[^"\']+)["\'][^>]*>/i', $html, $matches)) {
            // Ignore common legit embeds if we want, but in post_content ANY remote script is usually bad
            $src = $matches[1];
            if (strpos($src, 'youtube.com') === false && strpos($src, 'vimeo.com') === false) {
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
