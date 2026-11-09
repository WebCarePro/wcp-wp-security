<?php
namespace WebCareProScanner\Advisor;

if (!defined('ABSPATH')) {
    exit;
}

use WebCareProScanner\System\SettingsManager;
use WebCareProScanner\System\AuditLogger;

/**
 * SiteAdvisorEngine
 *
 * Core recommendation synthesizer and snapshot manager.
 * Evaluates the detected SiteCapabilityProfile against PolicyRegistry,
 * generates an evidence-driven state matrix, and enforces conflict-aware rollbacks.
 *
 * @package WebCareProScanner\Advisor
 * @author Mir Alamin (WebCare Pro)
 */
class SiteAdvisorEngine {

    public const OPTION_SNAPSHOT = 'webcareproscan_advisor_last_snapshot';

    // Advisor States
    public const STATE_ALREADY_PROTECTED   = 'already_protected';
    public const STATE_ACTIVE_EXEMPTION    = 'active_exemption';
    public const STATE_RECOMMENDED_ENABLE  = 'recommended_to_enable';
    public const STATE_MONITOR_FIRST       = 'monitor_first';
    public const STATE_EXEMPTION_REVIEW    = 'compatibility_review';
    public const STATE_STALE_EXEMPTION     = 'stale_exemption';
    public const STATE_NEEDS_CONFIGURATION = 'needs_configuration';
    public const STATE_NOT_APPLICABLE      = 'not_applicable';

    /**
     * Generate full evaluation containing profile, recommendations, metrics, and active snapshot.
     *
     * @return array
     */
    public static function evaluate(): array {
        $profile  = SiteCapabilityProfiler::profile();
        $policies = PolicyRegistry::get_policies();
        $settings = SettingsManager::get_settings();

        $recommendations = [];
        $metrics = [
            'protected_count'    => 0,
            'recommended_count'  => 0,
            'monitor_count'      => 0,
            'stale_count'        => 0,
            'exemption_count'    => 0,
            'needs_config_count' => 0,
        ];

        foreach ($policies as $key => $policy) {
            $eval = self::evaluate_policy($key, $policy, $profile, $settings);
            $recommendations[$key] = $eval;

            switch ($eval['state']) {
                case self::STATE_ALREADY_PROTECTED:
                    $metrics['protected_count']++;
                    break;
                case self::STATE_ACTIVE_EXEMPTION:
                    $metrics['exemption_count']++;
                    break;
                case self::STATE_RECOMMENDED_ENABLE:
                    $metrics['recommended_count']++;
                    break;
                case self::STATE_MONITOR_FIRST:
                    $metrics['monitor_count']++;
                    break;
                case self::STATE_STALE_EXEMPTION:
                    $metrics['stale_count']++;
                    break;
                case self::STATE_NEEDS_CONFIGURATION:
                    $metrics['needs_config_count']++;
                    break;
            }
        }

        $snapshot = get_option(self::OPTION_SNAPSHOT, null);

        return [
            'profile'         => $profile,
            'metrics'         => $metrics,
            'recommendations' => $recommendations,
            'snapshot'        => $snapshot,
            'evaluated_at'    => gmdate('Y-m-d H:i:s'),
        ];
    }

    /**
     * Evaluate a single policy against profile and current settings.
     *
     * @param string $key
     * @param array $policy
     * @param array $profile
     * @param array $settings
     * @return array
     */
    private static function evaluate_policy(string $key, array $policy, array $profile, array $settings): array {
        $capabilities = $profile['capabilities'];
        $proxy        = $profile['proxy'];

        // Determine if any trigger capability is active
        $has_capability = empty($policy['trigger_capability']); // Universal policies have no triggers
        $trigger_evidence = [];

        foreach ($policy['trigger_capability'] as $cap) {
            if (!empty($capabilities[$cap]['detected'])) {
                $has_capability = true;
                $trigger_evidence[$cap] = $capabilities[$cap]['evidence'];
            }
        }

        $current_raw = $settings[$key] ?? null;
        $is_bool_type = is_bool($policy['target_value']);
        $current_val  = $is_bool_type ? !empty($current_raw) : (string) $current_raw;
        $target_val   = $policy['target_value'];

        $state = self::STATE_NOT_APPLICABLE;
        $proposed_value = null;
        $notes = '';

        // 1. Check if Stale Exemption (Capability absent, but exemption is turned on!)
        if (!$has_capability && $policy['type'] === PolicyRegistry::TYPE_EXEMPTION && $current_val === true) {
            $state          = self::STATE_STALE_EXEMPTION;
            $proposed_value = false; // Recommend disabling
            $notes          = __('The plugin or theme requiring this compatibility exemption is no longer active. Disabling this exemption tightens your attack surface.', 'webcare-pro-security');
        } elseif (!$has_capability) {
            $state = self::STATE_NOT_APPLICABLE;
        } else {
            // Capability IS present
            if ($policy['type'] === PolicyRegistry::TYPE_PROTECTION) {
                // If velocity rule requires IP trust but proxy topology is ambiguous, warn
                if ($policy['requires_ip_trust'] && $proxy['proxy_warning'] && $current_val === false) {
                    $state          = self::STATE_NEEDS_CONFIGURATION;
                    $proposed_value = $target_val;
                    $notes          = __('Edge proxy/CDN headers detected without trusted subnet configuration. Verify reverse-proxy IP headers before enabling IP lockout rules.', 'webcare-pro-security');
                } elseif ($policy['action_mode'] === PolicyRegistry::ACTION_MONITOR) {
                    if ($current_val === 'off' || empty($current_val)) {
                        $state          = self::STATE_MONITOR_FIRST;
                        $proposed_value = 'monitor';
                        $notes          = __('Keep on Monitor mode to inspect traffic before strict blocking to prevent false positives.', 'webcare-pro-security');
                    } else {
                        $state = self::STATE_ALREADY_PROTECTED;
                    }
                } else {
                    // Standard protection
                    if ($current_val === $target_val) {
                        $state = self::STATE_ALREADY_PROTECTED;
                    } else {
                        $state          = self::STATE_RECOMMENDED_ENABLE;
                        $proposed_value = $target_val;
                        $notes          = $policy['security_benefit'];
                    }
                }
            } else {
                // Compatibility Exemption
                if ($current_val === true) {
                    $state = self::STATE_ACTIVE_EXEMPTION;
                    $notes = $policy['security_benefit'];
                } else {
                    $state          = self::STATE_EXEMPTION_REVIEW;
                    $proposed_value = true;
                    $notes          = __('Optional compatibility exemption to prevent legitimate application traffic from triggering false positives.', 'webcare-pro-security');
                }
            }
        }

        return [
            'key'                => $key,
            'title'              => $policy['title'],
            'type'               => $policy['type'],
            'state'              => $state,
            'current_value'      => $current_val,
            'proposed_value'     => $proposed_value,
            'action_mode'        => $policy['action_mode'],
            'compatibility_risk' => $policy['compatibility_risk'],
            'description'        => $policy['description'],
            'security_benefit'   => $policy['security_benefit'],
            'notes'              => $notes,
            'evidence'           => $trigger_evidence,
        ];
    }

    /**
     * Atomically apply approved recommendations with a versioned snapshot.
     *
     * @param array $approved_keys Array of setting keys approved by admin (e.g. ['waf_woo_carding_protection' => true, ...])
     * @return array Result of the application
     */
    public static function apply_recommendations(array $approved_keys): array {
        if (!current_user_can('manage_options')) {
            return ['success' => false, 'message' => __('Unauthorized access.', 'webcare-pro-security')];
        }

        $policies         = PolicyRegistry::get_policies();
        $current_settings = SettingsManager::get_settings();
        $changes          = [];
        $updates          = [];

        foreach ($approved_keys as $key => $target_val) {
            if (!isset($policies[$key])) {
                continue; // Ignore unregistered keys
            }

            $current_raw = $current_settings[$key] ?? null;
            $is_bool     = is_bool($policies[$key]['target_value']);
            $current_val = $is_bool ? !empty($current_raw) : (string) $current_raw;

            // Only track if value actually differs
            if ($current_val !== $target_val) {
                $changes[$key] = [
                    'before'  => $current_val,
                    'applied' => $target_val,
                ];
                $updates[$key] = $target_val;
            }
        }

        if (empty($changes)) {
            return [
                'success' => true,
                'message' => __('All selected recommendations are already active. No changes needed.', 'webcare-pro-security'),
                'changed' => 0,
            ];
        }

        // Create versioned snapshot
        $snapshot = [
            'schema_version' => 1,
            'snapshot_id'    => wp_generate_uuid4(),
            'created_at'     => gmdate('Y-m-d H:i:s'),
            'actor_id'       => get_current_user_id(),
            'changes'        => $changes,
        ];

        // Save snapshot with autoload = false (0 bytes frontend memory)
        update_option(self::OPTION_SNAPSHOT, $snapshot, false);

        // Apply updates through official SettingsManager pathway
        SettingsManager::save_settings($updates);

        if (class_exists(AuditLogger::class)) {
            AuditLogger::log('site_advisor_applied', [
                'changed_count' => count($changes),
                'snapshot_id'   => $snapshot['snapshot_id'],
            ]);
        }

        // Post-Fix Store & Checkout Pulse Check
        $pulse = class_exists('\\WebCareProScanner\\System\\PulseHealthCheck')
            ? \WebCareProScanner\System\PulseHealthCheck::check_store_pulse()
            : ['all_passed' => true, 'has_fatal_conflict' => false, 'summary' => ''];

        // Only trigger automatic safety rollback if an endpoint verified a genuine fatal server crash (HTTP 500-504 or fatal PHP error)
        if (!empty($pulse['has_fatal_conflict'])) {
            self::rollback();
            return [
                'success'        => false,
                'rollback'       => true,
                'message'        => __('Safety Rollback Triggered: We noticed a potential site conflict immediately after applying recommendations, so we automatically undid the changes to keep your site and checkout online.', 'webcare-pro-security'),
                'pulse'          => $pulse,
                'changed'        => 0,
            ];
        }

        return [
            'success'     => true,
            'message'     => sprintf(
                /* translators: %d: number of settings updated */
                __('Site Advisor successfully optimized %d security settings.', 'webcare-pro-security'),
                count($changes)
            ),
            'changed'     => count($changes),
            'snapshot_id' => $snapshot['snapshot_id'],
            'pulse'       => $pulse,
        ];
    }

    /**
     * Conflict-aware rollback of the last snapshot.
     * Prevents silently clobbering manual edits made by an administrator since the Advisor ran.
     *
     * @return array
     */
    public static function rollback(): array {
        if (!current_user_can('manage_options')) {
            return ['success' => false, 'message' => __('Unauthorized access.', 'webcare-pro-security')];
        }

        $snapshot = get_option(self::OPTION_SNAPSHOT, null);
        if (empty($snapshot) || empty($snapshot['changes'])) {
            return ['success' => false, 'message' => __('No Site Advisor snapshot found to rollback.', 'webcare-pro-security')];
        }

        $current_settings = SettingsManager::get_settings();
        $policies         = PolicyRegistry::get_policies();
        $revert_updates   = [];
        $conflicts        = [];

        foreach ($snapshot['changes'] as $key => $change) {
            $current_raw = $current_settings[$key] ?? null;
            $is_bool     = isset($policies[$key]) && is_bool($policies[$key]['target_value']);
            $current_val = $is_bool ? !empty($current_raw) : (string) $current_raw;
            $applied_val = $change['applied'];

            // Strict normalized comparison
            if ($current_val === $applied_val) {
                // Safe to revert!
                $revert_updates[$key] = $change['before'];
            } else {
                // Conflict! Admin manually modified setting after Advisor ran.
                $conflicts[$key] = [
                    'current' => $current_val,
                    'applied' => $applied_val,
                    'before'  => $change['before'],
                ];
            }
        }

        if (!empty($revert_updates)) {
            SettingsManager::save_settings($revert_updates);
        }

        // Delete the rolled-back snapshot
        delete_option(self::OPTION_SNAPSHOT);

        if (class_exists(AuditLogger::class)) {
            AuditLogger::log('site_advisor_rollback', [
                'reverted_count'  => count($revert_updates),
                'conflicts_count' => count($conflicts),
                'snapshot_id'     => $snapshot['snapshot_id'] ?? 'unknown',
            ]);
        }

        return [
            'success'        => true,
            'reverted_count' => count($revert_updates),
            'conflicts'      => $conflicts,
            'message'        => empty($conflicts)
                ? sprintf(
                    /* translators: %d: number of settings reverted */
                    __('Successfully rolled back %d settings to previous baseline.', 'webcare-pro-security'),
                    count($revert_updates)
                )
                : sprintf(
                    /* translators: %1$d: reverted count, %2$d: conflict count */
                    __('Reverted %1$d settings. %2$d settings were skipped due to subsequent manual administrative overrides.', 'webcare-pro-security'),
                    count($revert_updates),
                    count($conflicts)
                ),
        ];
    }
}
