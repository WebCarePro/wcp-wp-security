/**
 * WCP Security Scanner - Global In-Page Action Modal & Popover Confirmation System
 *
 * Automatically intercepts or replaces native browser window.alert and window.confirm popups
 * on all WCP Security Scanner admin pages, rendering an elegant, accessible, theme-adaptive
 * in-page popover dialog positioned right near the triggering action button (or centered in viewport).
 *
 * @author Mir Alamin (WebCare Pro)
 */
(function() {
    'use strict';

    if (window.__WCP_POPOVER_INSTALLED__) return;
    window.__WCP_POPOVER_INSTALLED__ = true;

    // Track the most recently clicked / active element so popovers can anchor to it
    var lastTriggerEl = null;
    document.addEventListener('click', function(e) {
        if (e.target && (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.closest('button, a, [role="button"]'))) {
            lastTriggerEl = e.target.closest('button, a, [role="button"]') || e.target;
        }
    }, true);

    document.addEventListener('keydown', function(e) {
        if ((e.key === 'Enter' || e.key === ' ') && document.activeElement) {
            lastTriggerEl = document.activeElement;
        }
    }, true);

    // Create container for styles & popovers
    var styleEl = document.createElement('style');
    styleEl.id = 'wcp-popover-styles';
    styleEl.textContent = `
        .wcp-popover-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15, 23, 42, 0.45);
            backdrop-filter: blur(2px);
            z-index: 9999999;
            opacity: 0;
            transition: opacity 0.16s ease-out;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .wcp-popover-overlay.wcp-visible {
            opacity: 1;
        }
        .wcp-popover-card {
            position: absolute;
            width: 90vw;
            max-width: 440px;
            background: var(--wcp-bg-panel, #ffffff);
            color: var(--wcp-text-primary, #0f172a);
            border: 1px solid var(--wcp-border, #e2e8f0);
            border-radius: 14px;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(0, 0, 0, 0.05);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            padding: 20px;
            box-sizing: border-box;
            transform: scale(0.96) translateY(-4px);
            opacity: 0;
            transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1);
            z-index: 10000000;
        }
        .wcp-theme-dark .wcp-popover-card,
        [data-theme="dark"] .wcp-popover-card,
        body.wcp-theme-dark .wcp-popover-card {
            background: #0f172a !important;
            color: #f8fafc !important;
            border-color: rgba(255, 255, 255, 0.12) !important;
            box-shadow: 0 20px 40px -8px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.08) !important;
        }
        .wcp-popover-card.wcp-visible {
            transform: scale(1) translateY(0);
            opacity: 1;
        }
        .wcp-popover-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 12px;
        }
        .wcp-popover-icon-box {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            font-size: 18px;
        }
        .wcp-popover-icon-box.info {
            background: rgba(79, 70, 229, 0.1);
            color: #4f46e5;
        }
        .wcp-popover-icon-box.warning {
            background: rgba(245, 158, 11, 0.12);
            color: #d97706;
        }
        .wcp-popover-icon-box.danger {
            background: rgba(239, 68, 68, 0.12);
            color: #dc2626;
        }
        .wcp-popover-icon-box.success {
            background: rgba(16, 185, 129, 0.12);
            color: #059669;
        }
        .wcp-popover-title {
            margin: 0;
            font-size: 15px;
            font-weight: 700;
            line-height: 1.3;
            color: inherit;
        }
        .wcp-popover-body {
            font-size: 13px;
            line-height: 1.5;
            color: var(--wcp-text-secondary, #475569);
            white-space: pre-wrap;
            word-break: break-word;
            margin-bottom: 18px;
        }
        .wcp-theme-dark .wcp-popover-body,
        [data-theme="dark"] .wcp-popover-body,
        body.wcp-theme-dark .wcp-popover-body {
            color: #cbd5e1 !important;
        }
        .wcp-popover-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
        }
        .wcp-popover-btn {
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.15s ease;
            outline: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 34px;
        }
        .wcp-popover-btn-cancel {
            background: var(--wcp-bg-elevated, #f1f5f9);
            color: var(--wcp-text-primary, #334155);
            border-color: var(--wcp-border-strong, #cbd5e1);
        }
        .wcp-popover-btn-cancel:hover {
            background: #e2e8f0;
        }
        .wcp-theme-dark .wcp-popover-btn-cancel,
        [data-theme="dark"] .wcp-popover-btn-cancel,
        body.wcp-theme-dark .wcp-popover-btn-cancel {
            background: #1e293b !important;
            color: #e2e8f0 !important;
            border-color: rgba(255, 255, 255, 0.15) !important;
        }
        .wcp-popover-btn-confirm {
            background: #dc2626;
            color: #ffffff;
            border-color: #b91c1c;
            box-shadow: 0 2px 6px rgba(220, 38, 38, 0.25);
        }
        .wcp-popover-btn-confirm:hover {
            background: #b91c1c;
        }
        .wcp-popover-btn-confirm.is-primary {
            background: #4f46e5;
            border-color: #4338ca;
            box-shadow: 0 2px 6px rgba(79, 70, 229, 0.25);
        }
        .wcp-popover-btn-confirm.is-primary:hover {
            background: #4338ca;
        }
        .wcp-popover-arrow {
            position: absolute;
            width: 10px;
            height: 10px;
            background: inherit;
            border: inherit;
            transform: rotate(45deg);
            display: none;
        }
        .wcp-popover-card[data-arrow="bottom"] .wcp-popover-arrow {
            display: block;
            bottom: -6px;
            border-left: none;
            border-top: none;
        }
        .wcp-popover-card[data-arrow="top"] .wcp-popover-arrow {
            display: block;
            top: -6px;
            border-right: none;
            border-bottom: none;
        }
    `;
    document.head.appendChild(styleEl);

    /**
     * Compute anchor position near triggering button
     */
    function positionCard(card, triggerEl) {
        if (!triggerEl || typeof triggerEl.getBoundingClientRect !== 'function') {
            // Center in viewport
            card.style.top = '50%';
            card.style.left = '50%';
            card.style.transform = 'translate(-50%, -50%)';
            card.removeAttribute('data-arrow');
            return;
        }

        var rect = triggerEl.getBoundingClientRect();
        // Measure unscaled element layout dimensions for pixel-accurate positioning
        var cardWidth = card.offsetWidth || 380;
        var cardHeight = card.offsetHeight || 180;
        var vw = window.innerWidth;
        var vh = window.innerHeight;

        var targetTop = 0;
        var targetLeft = 0;
        var arrowPos = 'top';

        // Prefer placing above or below the button
        var spaceAbove = rect.top;
        var spaceBelow = vh - rect.bottom;

        if (spaceBelow >= cardHeight + 15 || spaceBelow >= spaceAbove) {
            // Below button
            targetTop = rect.bottom + 10;
            arrowPos = 'top';
        } else {
            // Above button
            targetTop = rect.top - cardHeight - 10;
            arrowPos = 'bottom';
        }

        // Align horizontally: center with button, keep within viewport padding
        targetLeft = rect.left + (rect.width / 2) - (cardWidth / 2);
        if (targetLeft < 15) targetLeft = 15;
        if (targetLeft + cardWidth > vw - 15) {
            targetLeft = vw - cardWidth - 15;
        }

        if (targetTop < 15) targetTop = 15;
        if (targetTop + cardHeight > vh - 15) {
            targetTop = vh - cardHeight - 15;
        }

        card.style.top = targetTop + 'px';
        card.style.left = targetLeft + 'px';
        card.style.transform = 'none';

        // Adjust arrow position
        card.setAttribute('data-arrow', arrowPos);
        var arrow = card.querySelector('.wcp-popover-arrow');
        if (arrow) {
            var arrowLeft = (rect.left + rect.width / 2) - targetLeft - 5;
            if (arrowLeft < 15) arrowLeft = 15;
            if (arrowLeft > cardWidth - 25) arrowLeft = cardWidth - 25;
            arrow.style.left = arrowLeft + 'px';
        }
    }

    /**
     * Show Popover / Modal Dialog
     */
    function showModalDialog(options) {
        var isConfirm = options.type === 'confirm';
        var message = options.message || '';
        var title = options.title || (isConfirm ? 'Confirm Action' : 'Notice');
        var variant = options.variant || (isConfirm ? 'danger' : 'info');
        var anchorEl = options.anchorEl || lastTriggerEl || document.activeElement;

        // Overlay
        var overlay = document.createElement('div');
        overlay.className = 'wcp-popover-overlay';

        // Card
        var card = document.createElement('div');
        card.className = 'wcp-popover-card';
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');

        var arrow = document.createElement('div');
        arrow.className = 'wcp-popover-arrow';
        card.appendChild(arrow);

        var header = document.createElement('div');
        header.className = 'wcp-popover-header';

        var iconBox = document.createElement('div');
        iconBox.className = 'wcp-popover-icon-box ' + variant;
        iconBox.textContent = (variant === 'danger' || variant === 'warning') ? '\u26A0\uFE0F' : (variant === 'success' ? '\u2714' : '\u2139\uFE0F');

        var titleEl = document.createElement('h4');
        titleEl.className = 'wcp-popover-title';
        titleEl.textContent = title;

        header.appendChild(iconBox);
        header.appendChild(titleEl);
        card.appendChild(header);

        var body = document.createElement('div');
        body.className = 'wcp-popover-body';
        body.textContent = message;
        card.appendChild(body);

        var actions = document.createElement('div');
        actions.className = 'wcp-popover-actions';

        var keyHandler = null;

        var close = function(result) {
            if (keyHandler) {
                window.removeEventListener('keydown', keyHandler);
                keyHandler = null;
            }
            overlay.classList.remove('wcp-visible');
            card.classList.remove('wcp-visible');
            setTimeout(function() {
                if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
                if (options.onResolve) options.onResolve(result);
            }, 180);
        };

        if (isConfirm) {
            var cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'wcp-popover-btn wcp-popover-btn-cancel';
            cancelBtn.textContent = options.cancelLabel || 'Cancel';
            cancelBtn.addEventListener('click', function(e) {
                e.preventDefault();
                close(false);
            });
            actions.appendChild(cancelBtn);

            var confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = 'wcp-popover-btn wcp-popover-btn-confirm' + (variant === 'info' || variant === 'success' ? ' is-primary' : '');
            confirmBtn.textContent = options.confirmLabel || 'Proceed';
            confirmBtn.addEventListener('click', function(e) {
                e.preventDefault();
                close(true);
            });
            actions.appendChild(confirmBtn);
        } else {
            var okBtn = document.createElement('button');
            okBtn.type = 'button';
            okBtn.className = 'wcp-popover-btn wcp-popover-btn-confirm is-primary';
            okBtn.textContent = options.okLabel || 'OK';
            okBtn.addEventListener('click', function(e) {
                e.preventDefault();
                close(true);
            });
            actions.appendChild(okBtn);
        }

        card.appendChild(actions);
        overlay.appendChild(card);
        document.body.appendChild(overlay);

        // Position card near trigger
        positionCard(card, anchorEl);

        // Animate in
        requestAnimationFrame(function() {
            overlay.classList.add('wcp-visible');
            card.classList.add('wcp-visible');
            if (isConfirm) {
                card.querySelector('.wcp-popover-btn-confirm').focus();
            } else {
                card.querySelector('.wcp-popover-btn').focus();
            }
        });

        // Close on ESC
        keyHandler = function(e) {
            if (e.key === 'Escape') {
                close(false);
            }
        };
        window.addEventListener('keydown', keyHandler);

        // Close on backdrop click
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) {
                close(false);
            }
        });
    }

    /**
     * Expose Global Public Helper
     */
    window.wcpConfirmPopover = function(options) {
        return new Promise(function(resolve) {
            showModalDialog(Object.assign({}, options, {
                type: 'confirm',
                onResolve: resolve
            }));
        });
    };

    window.wcpAlertPopover = function(options) {
        return new Promise(function(resolve) {
            var opts = (typeof options === 'string') ? { message: options } : options;
            showModalDialog(Object.assign({}, opts, {
                type: 'alert',
                onResolve: resolve
            }));
        });
    };

    // Inline floating tooltip / callout near input/button without modal backdrop
    window.wcpShowInlineCallout = function(anchorEl, message, type) {
        if (!anchorEl) return;
        type = type || 'error';

        // Remove any existing inline callout
        var existing = document.querySelector('.wcp-inline-callout');
        if (existing) existing.remove();

        var callout = document.createElement('div');
        callout.className = 'wcp-inline-callout';
        callout.style.position = 'absolute';
        callout.style.background = (type === 'error') ? '#fef2f2' : (type === 'success' ? '#ecfdf5' : '#eff6ff');
        callout.style.color = (type === 'error') ? '#991b1b' : (type === 'success' ? '#065f46' : '#1e40af');
        callout.style.border = '1px solid ' + ((type === 'error') ? '#fca5a5' : (type === 'success' ? '#a7f3d0' : '#bfdbfe'));
        callout.style.borderRadius = '8px';
        callout.style.padding = '8px 14px';
        callout.style.fontSize = '12px';
        callout.style.fontWeight = '600';
        callout.style.boxShadow = '0 6px 16px rgba(0, 0, 0, 0.12)';
        callout.style.zIndex = '999999';
        callout.style.display = 'flex';
        callout.style.alignItems = 'center';
        callout.style.gap = '8px';
        callout.style.animation = 'wcpModalIn 0.2s cubic-bezier(0.16, 1, 0.3, 1)';

        var icon = (type === 'error') ? '\u26A0\uFE0F ' : (type === 'success' ? '\u2714 ' : '\u2139\uFE0F ');
        var spanEl = document.createElement('span');
        spanEl.textContent = icon + String(message || '');
        callout.appendChild(spanEl);

        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.textContent = '\u00D7';
        closeBtn.style.background = 'none';
        closeBtn.style.border = 'none';
        closeBtn.style.fontSize = '16px';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.color = 'inherit';
        closeBtn.style.marginLeft = '6px';
        closeBtn.onclick = function() { callout.remove(); };
        callout.appendChild(closeBtn);

        document.body.appendChild(callout);

        var rect = anchorEl.getBoundingClientRect();
        var calloutRect = callout.getBoundingClientRect();

        var top = rect.top + window.scrollY - calloutRect.height - 8;
        if (top < 10) {
            top = rect.bottom + window.scrollY + 8;
        }
        var left = rect.left + window.scrollX;
        if (left + calloutRect.width > window.innerWidth - 15) {
            left = window.innerWidth - calloutRect.width - 15;
        }

        callout.style.top = top + 'px';
        callout.style.left = left + 'px';

        setTimeout(function() {
            if (callout.parentNode) callout.remove();
        }, 5000);
    };

    /**
     * Intercept window.alert on WCP Admin pages so that no native alert dialog ever pops up
     */
    var nativeAlert = window.alert;
    window.alert = function(msg) {
        // If we have an active trigger element, anchor near it
        window.wcpAlertPopover({
            title: 'WCP Security Scanner',
            message: String(msg || ''),
            variant: (String(msg).toLowerCase().includes('fail') || String(msg).toLowerCase().includes('error')) ? 'danger' : 'info',
            anchorEl: lastTriggerEl || document.activeElement
        });
    };

    /**
     * Store native confirm for fallback if needed
     */
    window.__wcpNativeConfirm = window.confirm;
    window.__wcpNativeAlert = nativeAlert;
})();
