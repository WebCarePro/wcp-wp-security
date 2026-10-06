<?php
namespace WCP\Scanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class RiskScorer {

    /**
     * Compute risk score (0-100), risk level, and count breakdown from a list of findings.
     *
     * @param Finding[]|array $findings
     * @return array
     */
    public function calculate($findings) {
        $counts = [
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'low'      => 0,
            'info'     => 0
        ];

        $raw_score = 0;

        foreach ($findings as $finding) {
            $f_data = is_array($finding) ? $finding : (method_exists($finding, 'to_array') ? $finding->to_array() : (array) $finding);
            $severity = strtolower($f_data['severity'] ?? 'medium');
            $confidence = isset($f_data['confidence']) ? floatval($f_data['confidence']) : 100;
            // Normalize confidence to 0.0 - 1.0
            $conf_factor = $confidence > 1.0 ? ($confidence / 100.0) : $confidence;

            if (isset($counts[$severity])) {
                $counts[$severity]++;
            } else {
                $counts['medium']++;
                $severity = 'medium';
            }

            // Weighted point system
            switch ($severity) {
                case 'critical':
                    $raw_score += 40 * $conf_factor;
                    break;
                case 'high':
                    $raw_score += 15 * $conf_factor;
                    break;
                case 'medium':
                    $raw_score += 5 * $conf_factor;
                    break;
                case 'low':
                    $raw_score += 1 * $conf_factor;
                    break;
                case 'info':
                default:
                    $raw_score += 0;
                    break;
            }
        }

        // Cap at 100
        $risk_score = min(100, (int) round($raw_score));

        // Assign risk level based on point 43 of specifications
        if ($risk_score >= 80) {
            $level = 'CRITICAL RISK';
        } elseif ($risk_score >= 60) {
            $level = 'HIGH RISK';
        } elseif ($risk_score >= 40) {
            $level = 'MODERATE RISK';
        } elseif ($risk_score >= 20) {
            $level = 'LOW RISK';
        } else {
            $level = 'CLEAN / VERY LOW RISK';
        }

        return [
            'score'       => $risk_score,
            'level'       => $level,
            'counts'      => $counts,
            'total'       => count($findings)
        ];
    }
}
