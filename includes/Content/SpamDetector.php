<?php
namespace WCP\Scanner\Content;

if (!defined('ABSPATH')) {
    exit;
}

class SpamDetector {

    private $spam_categories = [
        'pharmacy_spam' => [
            'terms'      => ['viagra', 'cialis', 'levitra', 'phentermine', 'kamagra', 'tramadol', 'buy cheap pills', 'online pharmacy no prescription'],
            'severity'   => 'high',
            'desc'       => 'Pharmaceutical / rogue pharmacy spam keywords detected.'
        ],
        'gambling_spam' => [
            'terms'      => ['slot gacor', 'judi online', 'sbobet', 'poker online', 'casino online', 'roulette bonus', 'judi slot', 'free spin casino', 'betting bonus'],
            'severity'   => 'high',
            'desc'       => 'Casino / online gambling SEO spam keywords detected.'
        ],
        'crypto_spam' => [
            'terms'      => ['crypto giveaway', 'bitcoin doubler', 'recovery scam', 'guaranteed roi', 'crypto investment pool'],
            'severity'   => 'medium',
            'desc'       => 'Cryptocurrency / financial recovery scam keywords detected.'
        ]
    ];

    /**
     * Inspect text/HTML content for spam patterns.
     *
     * @param string $content
     * @return array List of findings details
     */
    public function analyze($content) {
        $findings = [];

        if (empty($content) || !is_string($content)) {
            return $findings;
        }

        $lower = strtolower($content);

        // 1. Check keyword category hits
        foreach ($this->spam_categories as $key => $cat) {
            $matched = [];
            foreach ($cat['terms'] as $term) {
                if (strpos($lower, $term) !== false) {
                    $matched[] = $term;
                }
            }

            if (count($matched) >= 2 || (count($matched) === 1 && strlen($content) < 500)) {
                $category_names = [
                    'pharmacy_spam' => 'Illicit Online Pharmacy / Controlled Prescription Drug Promotion',
                    'gambling_spam' => 'Unlicensed Online Casino / Gambling Backlink Injection',
                    'crypto_spam'   => 'Cryptocurrency Doubler / Financial Recovery Scam',
                ];
                $cat_detail = $category_names[$key] ?? 'SEO Spam Vector';
                $terms_list = implode(', ', $matched);
                $findings[] = [
                    'type'       => $key,
                    'severity'   => $cat['severity'],
                    'confidence' => 85,
                    'desc'       => "{$cat['desc']} Matched keyword(s): [{$terms_list}]. Black-hat SEO spam pattern ({$cat_detail}) attempting link-building or doorway manipulation.",
                    'evidence'   => 'Matched terms: ' . $terms_list
                ];
            }
        }

        // 2. Check for Japanese SEO hack / Doorway injection (burst of Japanese characters in content)
        // Japanese Hiragana/Katakana unicode ranges: \x{3040}-\x{309F}, \x{30A0}-\x{30FF}
        if (preg_match_all('/[\x{3040}-\x{309F}\x{30A0}-\x{30FF}]/u', $content, $matches) > 30) {
            $site_lang = get_locale();
            if (strpos($site_lang, 'ja') !== 0) {
                $findings[] = [
                    'type'       => 'japanese_seo_keyword_hack',
                    'severity'   => 'high',
                    'confidence' => 90,
                    'desc'       => 'Large density of Japanese characters detected on non-Japanese site (Japanese SEO hack signature).',
                    'evidence'   => 'Character count: ' . count($matches[0])
                ];
            }
        }

        return $findings;
    }
}
