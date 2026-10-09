<?php
namespace WCP\Scanner\Findings;

if (!defined('ABSPATH')) {
    exit;
}

class CorrelationEngine {

    /**
     * Correlate findings across multiple engines to identify high-confidence compound threats.
     *
     * @param Finding[] $findings
     * @return Finding[] Correlated and elevated findings
     */
    public function correlate($findings) {
        if (empty($findings)) {
            return [];
        }

        // Group findings by file_path or target identifier
        $grouped = [];
        foreach ($findings as $idx => $finding) {
            $key = trim($finding->file_path);
            if (empty($key)) {
                $key = '__global__' . $idx;
            }
            $grouped[$key][] = $finding;
        }

        $correlated_findings = [];

        foreach ($grouped as $target => $target_findings) {
            $norm_target = str_replace('\\', '/', $target);
            if (strpos($norm_target, '/plugins/wcp-wp-scanner/') !== false || strpos($norm_target, '/plugins/wcp-security-scanner/') !== false || strpos($norm_target, '/tests/') !== false) {
                continue; // Always drop findings on scanner's own code
            }

            if (count($target_findings) === 1) {
                $correlated_findings[] = $target_findings[0];
                continue;
            }

            // Multiple findings for the same target! Check if from different engines
            $engines = [];
            $types = [];
            foreach ($target_findings as $f) {
                $engines[$f->engine] = true;
                $types[$f->type] = true;
            }

            $unique_engines = array_keys($engines);

            // Pattern 1: Modified Core/Plugin + Malware Heuristic / Obfuscation
            $has_integrity = isset($engines['integrity-core']) || isset($engines['integrity-plugin']);
            $has_malware = isset($engines['malware-obfuscation']) || isset($engines['malware-webshell']) || isset($engines['malware-strings']);
            $is_upload = strpos($target, '/uploads/') !== false;

            if (($has_integrity && $has_malware) || ($is_upload && $has_malware)) {
                // Compound High-Confidence Threat!
                $reasons = [];
                if ($has_integrity) $reasons[] = 'modified checksum';
                if ($is_upload) $reasons[] = 'located in writable uploads directory';
                if (isset($engines['malware-webshell'])) $reasons[] = 'webshell command execution';
                if (isset($engines['malware-obfuscation'])) $reasons[] = 'obfuscated/encoded payload';

                $summary_evidence = "Multi-Engine Correlation Alert: [" . implode(' + ', $reasons) . "] detected on same target. Confirmed malicious attack vector.";

                foreach ($target_findings as $f) {
                    $f->severity = 'critical';
                    $f->confidence = 99;
                    $f->evidence = $f->evidence ? ($f->evidence . " | " . $summary_evidence) : $summary_evidence;
                    $f->description .= " [CORRELATED THREAT: Confirmed by multiple scanner engines]";
                    $correlated_findings[] = $f;
                }
            } else {
                // Keep original findings with slight confidence boost for multi-signal verification
                foreach ($target_findings as $f) {
                    if (count($unique_engines) > 1) {
                        $f->confidence = min(99, $f->confidence + 10);
                    }
                    $correlated_findings[] = $f;
                }
            }
        }

        return $correlated_findings;
    }
}
