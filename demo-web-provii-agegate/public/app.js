// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Age Verification Demo
 *
 * Demonstrates the correct integration pattern:
 * - All API calls go through the site backend (/v1/verify/*)
 * - HMAC secrets are never exposed to the client
 * - Session cookie set after successful verification
 *
 * SECURITY: The client never handles HMAC secrets or code_verifier values
 * directly. All sensitive operations are proxied through the backend.
 */

const MINIMUM_AGE = 18;
const POLL_INTERVAL = 2000;
const MAX_POLL_ATTEMPTS = 150;

/** Escape a string for safe insertion into HTML to prevent XSS. */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

class AgeVerificationDemo {
    constructor() {
        this.challengeId = null;
        this.codeVerifier = null;
        this.pollInterval = null;
        this.pollAttempts = 0;
        this.qrContainer = document.getElementById('qr-container');
        this.statusMessage = document.getElementById('status-message');
        this.ageGateOverlay = document.getElementById('age-gate-overlay');
        this.mainContent = document.getElementById('main-content');
        this.isVerified = false;

 // Resume polling when page becomes visible (e.g., returning from wallet app)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.challengeId && !this.isVerified && !this.pollInterval) {
                console.log('Page became visible, resuming polling...');
                this.updateStatus('Checking verification status...', 'loading');
                this.startPolling();
            }
        });
    }

    async init() {
        try {
            this.updateStatus('Creating verification challenge...', 'loading');
            await this.createChallenge();
        } catch (error) {
            console.error('Initialization error:', error);
            this.updateStatus(error.message || 'Failed to initialize', 'error');
            this.showRetryButton();
        }
    }

    async createChallenge() {
 // Call the site backend, not the verifier API directly
        const response = await fetch('/v1/verify/create-challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ minimumAge: MINIMUM_AGE }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create challenge');
        }

        const data = await response.json();
        this.challengeId = data.challenge_id;
        this.codeVerifier = data.code_verifier;

 // Render QR code or mobile button with full challenge data
        this.renderQRCode(data.verify_url, data);

 // Start polling
        this.startPolling();
    }

    renderQRCode(verifyUrl, challengeData) {
 // Clear the container first - IMPORTANT to avoid duplicates
        this.qrContainer.innerHTML = '';

 // Detect mobile device
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        const challengeId = challengeData.challenge_id;

 // Create deep link for mobile app
 // Format: https://provii.app/verify?d={base64url_encoded_json}
        const deepLinkData = {
            challenge_id: challengeId,
            rp_challenge: challengeData.rp_challenge,
            submit_secret: challengeData.submit_secret,
            cutoff_days: challengeData.cutoff_days,
            verifying_key_id: challengeData.verifying_key_id,
            verify_url: challengeData.verify_url,
            expires_at: challengeData.expires_at
        };
        const deepLinkJson = JSON.stringify(deepLinkData);
        const deepLinkB64 = btoa(deepLinkJson)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        const deepLink = `https://provii.app/verify?d=${deepLinkB64}`;

 // On mobile, show a big button instead of QR code
        if (isMobile) {
            const mobileWrapper = document.createElement('div');
            mobileWrapper.style.textAlign = 'center';
            mobileWrapper.style.padding = '20px';

            const button = document.createElement('a');
            button.href = deepLink;
            button.style.cssText = `
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 24px 48px;
                border-radius: 16px;
                text-decoration: none;
                font-size: 20px;
                font-weight: 700;
                box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
                transition: transform 0.2s, box-shadow 0.2s;
            `;
            button.textContent = '🎫 Open Provii Wallet';

            button.addEventListener('mouseover', () => {
                button.style.transform = 'translateY(-2px)';
                button.style.boxShadow = '0 12px 32px rgba(102, 126, 234, 0.5)';
            });
            button.addEventListener('mouseout', () => {
                button.style.transform = '';
                button.style.boxShadow = '0 8px 24px rgba(102, 126, 234, 0.4)';
            });

            mobileWrapper.appendChild(button);

 // Add challenge ID for reference
            const challengeIdDiv = document.createElement('div');
            challengeIdDiv.style.marginTop = '24px';
            challengeIdDiv.style.padding = '12px';
            challengeIdDiv.style.background = '#f5f5f7';
            challengeIdDiv.style.borderRadius = '8px';
            challengeIdDiv.style.fontFamily = 'SF Mono, Monaco, monospace';
            challengeIdDiv.style.fontSize = '12px';
            challengeIdDiv.style.color = '#1d1d1f';
            challengeIdDiv.innerHTML = `
                <div style="font-size: 11px; color: #86868b; margin-bottom: 4px;">Challenge ID (for manual entry):</div>
                <div style="font-size: 14px; font-weight: 500; letter-spacing: 0.5px; user-select: all;">${escapeHtml(challengeId)}</div>
            `;
            mobileWrapper.appendChild(challengeIdDiv);

            this.qrContainer.appendChild(mobileWrapper);
            this.updateStatus('Tap the button to open Provii Wallet', 'loading');
            return;
        }

 // Desktop: show QR code
 // Create a wrapper for the QR code and challenge ID
        const wrapper = document.createElement('div');
        wrapper.style.textAlign = 'center';

 // Create a div for the QR code
        const qrDiv = document.createElement('div');
        qrDiv.id = 'qrcode';
        qrDiv.style.display = 'inline-block';
        qrDiv.style.background = 'white';
        qrDiv.style.padding = '16px';
        qrDiv.style.borderRadius = '8px';
        wrapper.appendChild(qrDiv);

 // Generate QR code using QRCode library
 // IMPORTANT: QR code should only contain the challenge ID, not the full deep link
 // The mobile app will fetch the full challenge data from the verifier API
        const qrPayload = JSON.stringify({ challenge_id: challengeId });

        try {
 // Clear any existing QR code first
            qrDiv.innerHTML = '';

            const qr = new QRCode(qrDiv, {
                text: qrPayload,
                width: 280,
                height: 280,
                colorDark: '#000000',
                colorLight: '#FFFFFF',
                correctLevel: QRCode.CorrectLevel.M
            });

 // QRCode.js creates both canvas and img elements
 // We need to ensure only the canvas is visible
            setTimeout(() => {
                const qrImg = qrDiv.querySelector('img');
                const qrCanvas = qrDiv.querySelector('canvas');

                if (qrImg) {
                    qrImg.remove(); // Remove the img element entirely
                }

                if (qrCanvas) {
                    qrCanvas.style.display = 'block';
                    qrCanvas.style.margin = '0 auto';
                }
            }, 0);

 // Add challenge ID for accessibility
            const challengeIdDiv = document.createElement('div');
            challengeIdDiv.style.marginTop = '16px';
            challengeIdDiv.style.padding = '12px';
            challengeIdDiv.style.background = '#f5f5f7';
            challengeIdDiv.style.borderRadius = '8px';
            challengeIdDiv.style.fontFamily = 'SF Mono, Monaco, monospace';
            challengeIdDiv.style.fontSize = '12px';
            challengeIdDiv.style.color = '#1d1d1f';
            challengeIdDiv.innerHTML = `
                <div style="font-size: 11px; color: #86868b; margin-bottom: 4px;">Challenge ID (for manual entry):</div>
                <div style="font-size: 14px; font-weight: 500; letter-spacing: 0.5px; user-select: all;">${escapeHtml(challengeId)}</div>
            `;
            wrapper.appendChild(challengeIdDiv);

            this.updateStatus('Scan with Provii Wallet to verify your age', 'loading');

            this.qrContainer.appendChild(wrapper);
        } catch (error) {
            console.error('Failed to generate QR code:', error);
 // Fallback to showing just the deep link
            this.qrContainer.innerHTML = `
                <div style="text-align: center; padding: 20px;">
                    <p style="margin-bottom: 16px;">Unable to generate QR code</p>
                    <div style="padding: 16px; background: #f5f5f7; border-radius: 8px; margin-bottom: 12px;">
                        <div style="font-size: 11px; color: #86868b; margin-bottom: 8px;">Deep Link:</div>
                        <div style="font-family: 'SF Mono', Monaco, monospace; font-size: 12px; word-break: break-all; user-select: all;">
                            <a href="${escapeHtml(deepLink)}" style="color: #007AFF;">${escapeHtml(deepLink.substring(0, 50))}...</a>
                        </div>
                    </div>
                    <div style="padding: 12px; background: #f5f5f7; border-radius: 8px;">
                        <div style="font-size: 11px; color: #86868b; margin-bottom: 4px;">Challenge ID:</div>
                        <div style="font-family: 'SF Mono', Monaco, monospace; font-size: 14px; font-weight: 500; user-select: all;">${escapeHtml(challengeId)}</div>
                    </div>
                </div>
            `;
        }
    }

    startPolling() {
        this.pollAttempts = 0;
        this.pollInterval = setInterval(() => this.pollStatus(), POLL_INTERVAL);
    }

    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    async pollStatus() {
        try {
            this.pollAttempts++;

            if (this.pollAttempts > MAX_POLL_ATTEMPTS) {
                this.stopPolling();
                this.updateStatus('Verification timeout. Please try again.', 'error');
                this.showRetryButton();
                return;
            }

 // Poll through the site backend
            const response = await fetch('/v1/verify/poll', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challengeId: this.challengeId }),
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Poll failed');
            }

            const data = await response.json();

 // Update status message
            if (this.pollAttempts % 5 === 0) {
                this.updateStatus(`Waiting for verification... (${this.pollAttempts} attempts)`, 'loading');
            }

 // Check if verified
            if (data.status === 'verified' || data.status === 'proof_ok_waiting_for_redeem') {
                this.stopPolling();
                await this.handleVerified();
            } else if (data.status === 'rejected' || data.status === 'failed') {
                this.stopPolling();
                this.updateStatus('Verification rejected. You must be 18+ to access this content.', 'error');
                this.showRetryButton();
            }
        } catch (error) {
            console.error('Poll error:', error);
            this.stopPolling();
            this.updateStatus(error.message || 'Polling failed', 'error');
            this.showRetryButton();
        }
    }

    async handleVerified() {
 // Prevent double redemption
        if (this.isVerified) {
            console.log('Already verified, skipping redemption');
            return;
        }
        this.isVerified = true;

        try {
            this.updateStatus('Verification successful! Redeeming...', 'success');

 // Redeem through the site backend, which sets a session cookie
            const response = await fetch('/v1/verify/redeem', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    challengeId: this.challengeId,
                    codeVerifier: this.codeVerifier
                }),
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Redemption failed');
            }

            const data = await response.json();
            console.log('Redemption result:', data);

 // Show success and transition
            this.updateStatus('✓ Verified! Granting access...', 'success');

            setTimeout(() => {
                this.showMainContent();
            }, 1500);

        } catch (error) {
            console.error('Redemption error:', error);
            this.isVerified = false; // Allow retry
            this.updateStatus(error.message || 'Failed to complete verification', 'error');
            this.showRetryButton();
        }
    }

    showMainContent() {
 // Launch confetti!
        if (window.launchConfetti) {
            window.launchConfetti();
        }

 // Fade out age gate
        this.ageGateOverlay.style.transition = 'opacity 0.5s ease';
        this.ageGateOverlay.style.opacity = '0';

        setTimeout(() => {
 // Hide age gate
            this.ageGateOverlay.classList.add('hidden');
            this.ageGateOverlay.style.display = 'none';

 // Show main content
            this.mainContent.classList.remove('hidden');
            this.mainContent.style.display = 'block';

 // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }, 500);
    }

    updateStatus(message, type = 'loading') {
        const safeMessage = escapeHtml(message);
        this.statusMessage.className = `status-message ${type}`;

        if (type === 'loading') {
            this.statusMessage.innerHTML = `
                <div class="spinner"></div>
                <span>${safeMessage}</span>
            `;
        } else if (type === 'success') {
            this.statusMessage.innerHTML = `
                <svg viewBox="0 0 20 20" fill="currentColor" style="width:20px;height:20px;">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
                <span>${safeMessage}</span>
            `;
        } else if (type === 'error') {
            this.statusMessage.innerHTML = `
                <svg viewBox="0 0 20 20" fill="currentColor" style="width:20px;height:20px;">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                </svg>
                <span>${safeMessage}</span>
            `;
        }
    }

    showRetryButton() {
        this.qrContainer.innerHTML = `
            <div style="text-align:center;padding:40px;">
                <svg style="width:64px;height:64px;color:#FF9500;margin:0 auto 24px;display:block;" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
                </svg>
                <h3 style="margin-bottom:16px;color:#1d1d1f;">Something went wrong</h3>
                <button id="retry-btn" class="btn-primary" style="padding:12px 32px;font-size:16px;">
                    Try Again
                </button>
            </div>
        `;

        document.getElementById('retry-btn').addEventListener('click', () => {
            this.init();
        });
    }

    cleanup() {
        this.stopPolling();
    }
}

// Initialize the demo when page loads
let demo;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        demo = new AgeVerificationDemo();
        demo.init();
    });
} else {
    demo = new AgeVerificationDemo();
    demo.init();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (demo) {
        demo.cleanup();
    }
});
