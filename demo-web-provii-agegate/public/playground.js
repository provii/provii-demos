/**
 * Sandbox Credentials page - client-side logic.
 *
 * Two top-level role tabs:
 * - Verifier: pick a policy, mint a verifier credential triple, render
 * Simple / Expert / Mobile snippets.
 * - Issuer: pick a label, mint an Issuing Party credential bundle
 * (client_id + HMAC), render Node / Go / Python / cURL snippets that
 * authenticate to /v1/attestation/create. The Issuer signs every
 * attestation server-side; the Issuing Party never holds a signing key.
 *
 * Each role persists its credential bundle to localStorage and is fully
 * restored on reload.
 *
 * Hash routing: #verifier and #issuer select the active role. Tab clicks
 * update the hash. Hash changes update the active tab so deep links and
 * back/forward navigation work.
 */
(function () {
  'use strict';

 // ==========================================================================
 // Shared state + DOM lookups
 // ==========================================================================

  var VERIFIER_STORAGE_KEY = 'provii.playground.verifier.v1';
  var ISSUER_STORAGE_KEY = 'provii.playground.issuer.v1';
  var MODE_STORAGE_KEY = 'provii.playground.mode';
  var VALID_MODES = ['simple', 'expert', 'mobile'];
  var VALID_ROLES = ['verifier', 'issuer'];

 // Threshold (in seconds) at which the expiry warning banner appears. 4h
 // matches the spec; tweak here rather than scattering magic numbers.
  var EXPIRY_WARNING_WINDOW_SECONDS = 4 * 60 * 60;

  var liveStatus = document.getElementById('live-status');

 // Role tab elements.
  var roleTabs = Array.from(document.querySelectorAll('.pg-role-tab'));
  var rolePanels = {
    verifier: document.getElementById('role-panel-verifier'),
    issuer: document.getElementById('role-panel-issuer'),
  };

 // Verifier elements.
  var sectionVerifierForm = document.getElementById('section-verifier-form');
  var sectionVerifierResults = document.getElementById('section-verifier-results');
  var ageSelect = document.getElementById('age-select');
  var ageInput = document.getElementById('age-input');
  var customAgeWrapper = document.getElementById('custom-age-wrapper');
  var createBtn = document.getElementById('create-btn');
  var formAlert = document.getElementById('form-alert');
  var ageError = document.getElementById('age-error');
  var policyBanner = document.getElementById('policy-banner');
  var credPublicKey = document.getElementById('cred-public-key');
  var credClientId = document.getElementById('cred-client-id');
  var credHmacSecret = document.getElementById('cred-hmac-secret');
  var credApiKey = document.getElementById('cred-api-key');
  var credExpires = document.getElementById('cred-expires');
  var credentialsBlurb = document.getElementById('credentials-blurb');
  var credentialRows = document.querySelectorAll('[data-cred-field]');
  var resetBtn = document.getElementById('reset-btn');
  var copyAllBtn = document.getElementById('copy-all-btn');
  var copyAllStatus = document.getElementById('copy-all-status');
  var verifierExpiryWarning = document.getElementById('verifier-expiry-warning');
  var verifierExpiryRelative = document.getElementById('verifier-expiry-relative');
  var verifierTimeRemaining = document.getElementById('verifier-time-remaining');
  var verifierRemintBtn = document.getElementById('verifier-remint-btn');

  var snippetTargets = {
    'simple-agegate': document.getElementById('code-simple-agegate'),
    'expert-curl': document.getElementById('code-expert-curl'),
    'expert-nodejs': document.getElementById('code-expert-nodejs'),
    'expert-python': document.getElementById('code-expert-python'),
    'expert-go': document.getElementById('code-expert-go'),
    'mobile-ios': document.getElementById('code-mobile-ios'),
    'mobile-android': document.getElementById('code-mobile-android'),
    'mobile-flutter': document.getElementById('code-mobile-flutter'),
  };

  var modeTabs = document.querySelectorAll('.mode-tab');
  var modePanels = document.querySelectorAll('.pg-mode-panel');

 // Issuer elements.
  var sectionIssuerForm = document.getElementById('section-issuer-form');
  var sectionIssuerResults = document.getElementById('section-issuer-results');
  var issuerLabelInput = document.getElementById('issuer-label-input');
  var issuerLabelError = document.getElementById('issuer-label-error');
  var issuerFormAlert = document.getElementById('issuer-form-alert');
  var issuerCreateBtn = document.getElementById('issuer-create-btn');
  var issuerCredClientId = document.getElementById('issuer-cred-client-id');
  var issuerCredHmacSecret = document.getElementById('issuer-cred-hmac-secret');
  var issuerCredKid = document.getElementById('issuer-cred-kid');
  var issuerCredBaseUrl = document.getElementById('issuer-cred-base-url');
  var issuerCredExpires = document.getElementById('issuer-cred-expires');
  var issuerCredHeading = document.getElementById('issuer-cred-heading');
  var issuerResetBtn = document.getElementById('issuer-reset-btn');
  var issuerExpiryWarning = document.getElementById('issuer-expiry-warning');
  var issuerExpiryRelative = document.getElementById('issuer-expiry-relative');
  var issuerTimeRemaining = document.getElementById('issuer-time-remaining');
  var issuerRemintBtn = document.getElementById('issuer-remint-btn');
  var issuerCopyAllBtn = document.getElementById('issuer-copy-all-btn');
  var issuerCopyAllStatus = document.getElementById('issuer-copy-all-status');

 // Most recent issuer mint, used by the Copy-all-as-env-vars button.
 // Rehydrated from localStorage on load.
  var lastIssuerCredentials = null;

  var issuerSnippetTargets = {
    nodejs: document.getElementById('issuer-code-nodejs'),
    go: document.getElementById('issuer-code-go'),
    python: document.getElementById('issuer-code-python'),
    curl: document.getElementById('issuer-code-curl'),
  };

 // Track last-used verifier policy so the form repopulates on reset (WCAG
 // 3.3.7). lastCredentials is the most recent verifier mint, used by the
 // Copy-all-as-env-vars button and rehydrated from localStorage on load.
  var lastAge = 18;
  var lastDirection = 'over';
  var lastCredentials = null;

 // Per-mode credential visibility rules for the verifier panel. Simple
 // hides secrets because the script tag never needs them on the page.
  var CREDENTIAL_FIELDS_BY_MODE = {
    simple: ['publicKey', 'expiresAt'],
    expert: ['publicKey', 'clientId', 'hmacSecret', 'apiKey', 'expiresAt'],
    mobile: ['publicKey', 'clientId', 'hmacSecret', 'apiKey', 'expiresAt'],
  };

 // Tick handle for the time-remaining label so we don't stack intervals.
  var timeRemainingInterval = null;

 // ==========================================================================
 // Utilities
 // ==========================================================================

  function announce(message) {
    if (liveStatus) liveStatus.textContent = message;
  }

  function safeReadStorage(key) {
    try {
      var raw = window.localStorage.getItem(key);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch (_e) {
      return null;
    }
  }

  function safeWriteStorage(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (_e) { /* localStorage full or disabled, fail quietly */ }
  }

  function safeClearStorage(key) {
    try { window.localStorage.removeItem(key); } catch (_e) { /* ignore */ }
  }

  function nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  /**
 * Format a duration to "Xh Ym" or "Xm" or "Xs" precision. Used by both
 * the time-remaining label and the expiry warning relative phrase.
   */
  function formatDuration(secondsRemaining) {
    if (secondsRemaining <= 0) return 'expired';
    if (secondsRemaining < 60) return secondsRemaining + 's';
    if (secondsRemaining < 60 * 60) {
      return Math.floor(secondsRemaining / 60) + 'm';
    }
    var hours = Math.floor(secondsRemaining / 3600);
    var mins = Math.floor((secondsRemaining % 3600) / 60);
    if (mins === 0) return hours + 'h';
    return hours + 'h ' + mins + 'm';
  }

  function formatExpiresAbsolute(expiresAt) {
    if (!expiresAt) return '';
    return new Date(expiresAt * 1000).toLocaleString(undefined, {
      timeZone: 'UTC',
      timeZoneName: 'short',
    });
  }

 // ==========================================================================
 // Role tab routing
 // ==========================================================================

  function getRoleFromHash() {
    var raw = (window.location.hash || '').replace(/^#/, '').toLowerCase();
    return VALID_ROLES.indexOf(raw) !== -1 ? raw : 'verifier';
  }

  function setActiveRole(role, opts) {
    var options = opts || {};
    if (VALID_ROLES.indexOf(role) === -1) role = 'verifier';
    roleTabs.forEach(function (tab) {
      var isActive = tab.getAttribute('data-role') === role;
      tab.setAttribute('aria-selected', isActive ? 'true' : 'false');
      tab.setAttribute('tabindex', isActive ? '0' : '-1');
    });
    Object.keys(rolePanels).forEach(function (key) {
      var panel = rolePanels[key];
      if (!panel) return;
      panel.hidden = key !== role;
    });
    if (options.updateHash !== false) {
      var nextHash = '#' + role;
      if (window.location.hash !== nextHash) {
 // Use replaceState to avoid polluting back-button history with
 // every tab toggle. Deep links still work because we read the
 // hash on load and on hashchange.
        try {
          window.history.replaceState(null, '', nextHash);
        } catch (_e) {
          window.location.hash = nextHash;
        }
      }
    }
    if (options.focusTab) {
      var activeTab = document.getElementById('role-tab-' + role);
      if (activeTab) activeTab.focus();
    }
  }

  function bindRoleTabs() {
    roleTabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var role = tab.getAttribute('data-role');
        setActiveRole(role, { updateHash: true });
      });
      tab.addEventListener('keydown', function (e) {
        var index = roleTabs.indexOf(e.target);
        if (index < 0) return;
        var nextIndex = -1;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') nextIndex = (index + 1) % roleTabs.length;
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') nextIndex = (index - 1 + roleTabs.length) % roleTabs.length;
        else if (e.key === 'Home') nextIndex = 0;
        else if (e.key === 'End') nextIndex = roleTabs.length - 1;
        else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          var role = tab.getAttribute('data-role');
          setActiveRole(role, { updateHash: true });
          return;
        }
        if (nextIndex >= 0) {
          e.preventDefault();
          var nextRole = roleTabs[nextIndex].getAttribute('data-role');
          setActiveRole(nextRole, { updateHash: true, focusTab: true });
        }
      });
    });

    window.addEventListener('hashchange', function () {
      setActiveRole(getRoleFromHash(), { updateHash: false });
    });
  }

 // ==========================================================================
 // Verifier panel
 // ==========================================================================

  function showVerifierSection(name) {
    sectionVerifierForm.classList.toggle('section-hidden', name !== 'form');
    sectionVerifierResults.classList.toggle('section-hidden', name !== 'results');
  }

  function getSelectedAge() {
    if (ageSelect.value === 'custom') return parseInt(ageInput.value, 10);
    return parseInt(ageSelect.value, 10);
  }

  function getSelectedDirection() {
    var radios = document.querySelectorAll('input[name="direction"]');
    for (var i = 0; i < radios.length; i++) {
      if (radios[i].checked) return radios[i].value;
    }
    return 'over';
  }

  function clearVerifierErrors() {
    formAlert.style.display = 'none';
    formAlert.textContent = '';
    ageError.textContent = '';
    ageError.style.display = 'none';
    if (ageInput) ageInput.removeAttribute('aria-invalid');
    if (ageSelect) ageSelect.removeAttribute('aria-invalid');
  }

  function showVerifierFormError(message) {
    formAlert.textContent = message;
    formAlert.style.display = 'block';
  }

  function showAgeError(message) {
    ageError.textContent = message;
    ageError.style.display = 'block';
    if (ageSelect.value === 'custom') {
      ageInput.setAttribute('aria-invalid', 'true');
      ageInput.focus();
    } else {
      ageSelect.setAttribute('aria-invalid', 'true');
      ageSelect.focus();
    }
  }

  function readPersistedMode() {
    try {
      var stored = window.localStorage.getItem(MODE_STORAGE_KEY);
      if (stored && VALID_MODES.indexOf(stored) !== -1) return stored;
    } catch (_e) { /* ignore */ }
    return 'simple';
  }

  function persistMode(mode) {
    try { window.localStorage.setItem(MODE_STORAGE_KEY, mode); } catch (_e) { /* ignore */ }
  }

  function applyCredentialVisibility(mode) {
    var allowed = CREDENTIAL_FIELDS_BY_MODE[mode] || CREDENTIAL_FIELDS_BY_MODE.expert;
    credentialRows.forEach(function (row) {
      var field = row.getAttribute('data-cred-field');
      var visible = allowed.indexOf(field) !== -1;
      row.hidden = !visible;
    });
    if (credentialsBlurb) {
      if (mode === 'simple') {
        credentialsBlurb.textContent =
          'Origin-agnostic sandbox public key. Paste the snippet on any host and the SDK will work.';
      } else if (mode === 'mobile') {
        credentialsBlurb.textContent =
          'Origin-agnostic sandbox credentials. Keep the HMAC secret and API key on your backend; the mobile app only sees a pre-signed deep link.';
      } else {
        credentialsBlurb.textContent =
          'Origin-agnostic sandbox credentials. Store the HMAC secret server-side, never ship it to the browser.';
      }
    }
  }

  function activateMode(mode) {
    if (VALID_MODES.indexOf(mode) === -1) mode = 'simple';
    modeTabs.forEach(function (tab) {
      var isActive = tab.getAttribute('data-mode') === mode;
      tab.setAttribute('aria-selected', isActive ? 'true' : 'false');
      tab.setAttribute('tabindex', isActive ? '0' : '-1');
    });
    modePanels.forEach(function (panel) {
      var isActive = panel.id === 'mode-panel-' + mode;
      panel.hidden = !isActive;
    });
    applyCredentialVisibility(mode);
    persistMode(mode);
  }

  function getActiveMode() {
    var active = document.querySelector('.mode-tab[aria-selected="true"]');
    return active ? active.getAttribute('data-mode') || 'simple' : 'simple';
  }

  function buildEnvVarBlock(creds, mode) {
    var allowed = CREDENTIAL_FIELDS_BY_MODE[mode] || CREDENTIAL_FIELDS_BY_MODE.expert;
    var lines = [];
    if (allowed.indexOf('clientId') !== -1 && creds.clientId) {
      lines.push('PROVII_CLIENT_ID=' + creds.clientId);
    }
    if (allowed.indexOf('publicKey') !== -1 && creds.publicKey) {
      lines.push('PROVII_PUBLIC_KEY=' + creds.publicKey);
    }
    if (allowed.indexOf('hmacSecret') !== -1 && creds.hmacSecret) {
      lines.push('PROVII_HMAC_SECRET=' + creds.hmacSecret);
    }
    if (allowed.indexOf('apiKey') !== -1 && creds.apiKey) {
      lines.push('PROVII_API_KEY=' + creds.apiKey);
    }
    if (allowed.indexOf('expiresAt') !== -1 && creds.expiresAt) {
      lines.push('PROVII_EXPIRES_AT=' + creds.expiresAt);
    }
    return lines.join('\n');
  }

  /**
 * Render a verifier credential bundle into the DOM. Reused on a fresh
 * mint and on rehydrate-from-localStorage so the two paths stay in sync.
   */
  function renderVerifierCredentials(data) {
    if (!data) return;
    var dirLabel = data.direction === 'over' ? 'Over' : 'Under';
    if (data.age) policyBanner.textContent = 'Sandbox: ' + dirLabel + ' ' + data.age + ' verification';
    credPublicKey.textContent = data.publicKey || '';
    credClientId.textContent = data.clientId || '';
    credHmacSecret.textContent = data.hmacSecret || '';
    credApiKey.textContent = data.apiKey || '';
    if (data.expiresAt) credExpires.textContent = formatExpiresAbsolute(data.expiresAt);

    lastCredentials = {
      publicKey: data.publicKey || '',
      clientId: data.clientId || '',
      hmacSecret: data.hmacSecret || '',
      apiKey: data.apiKey || '',
      expiresAt: data.expiresAt || null,
    };

    if (data.codeSnippets) {
      var snippetMap = {
        'simple-agegate': data.codeSnippets.agegateJs,
        'expert-curl': data.codeSnippets.curl,
        'expert-nodejs': data.codeSnippets.nodejs,
        'expert-python': data.codeSnippets.python,
        'expert-go': data.codeSnippets.go,
        'mobile-ios': data.codeSnippets.iosSwift,
        'mobile-android': data.codeSnippets.androidKotlin,
        'mobile-flutter': data.codeSnippets.flutterDart,
      };
      Object.keys(snippetMap).forEach(function (key) {
        var target = snippetTargets[key];
        if (target) target.textContent = snippetMap[key] || '';
      });
    }

    activateMode(readPersistedMode());
    showVerifierSection('results');
    updateVerifierExpiryUi(data.expiresAt);
  }

  function updateVerifierExpiryUi(expiresAt) {
    if (!expiresAt) {
      verifierExpiryWarning.hidden = true;
      verifierTimeRemaining.textContent = '';
      return;
    }
    var remaining = expiresAt - nowSeconds();
    if (remaining <= 0) {
      verifierExpiryWarning.hidden = false;
      verifierExpiryRelative.textContent = 'Expired ' + formatDuration(-remaining) + ' ago.';
      verifierTimeRemaining.textContent = 'Expired.';
    } else if (remaining <= EXPIRY_WARNING_WINDOW_SECONDS) {
      verifierExpiryWarning.hidden = false;
      verifierExpiryRelative.textContent = 'Expires in ' + formatDuration(remaining) + '.';
      verifierTimeRemaining.textContent = 'Expires in ' + formatDuration(remaining) + ' (' + formatExpiresAbsolute(expiresAt) + ').';
    } else {
      verifierExpiryWarning.hidden = true;
      verifierTimeRemaining.textContent = 'Expires in ' + formatDuration(remaining) + ' (' + formatExpiresAbsolute(expiresAt) + ').';
    }
  }

  function clearVerifierFromStorage() {
    safeClearStorage(VERIFIER_STORAGE_KEY);
  }

  function persistVerifier(data) {
    safeWriteStorage(VERIFIER_STORAGE_KEY, {
      publicKey: data.publicKey || '',
      clientId: data.clientId || '',
      hmacSecret: data.hmacSecret || '',
      apiKey: data.apiKey || '',
      registeredOrigin: data.registeredOrigin || data.registered_origin || '',
      baseUrl: data.baseUrl || data.base_url || '',
      mintedAt: data.mintedAt || nowSeconds(),
      expiresAt: data.expiresAt || null,
      age: data.age,
      direction: data.direction,
      codeSnippets: data.codeSnippets || null,
    });
  }

  function rehydrateVerifier() {
    var stored = safeReadStorage(VERIFIER_STORAGE_KEY);
    if (!stored) return false;
    if (stored.expiresAt && stored.expiresAt <= nowSeconds()) {
 // Expired bundle: clear it and force the form. No legacy migration
 // logic; expired data is just dropped.
      clearVerifierFromStorage();
      return false;
    }
    if (typeof stored.age === 'number') lastAge = stored.age;
    if (typeof stored.direction === 'string') lastDirection = stored.direction;
    renderVerifierCredentials(stored);
    return true;
  }

 // Verifier form submit.
  createBtn.addEventListener('click', async function () {
    clearVerifierErrors();

    var age = getSelectedAge();
    var direction = getSelectedDirection();

    if (isNaN(age) || age < 5 || age > 25) {
      showAgeError('Please enter an age between 5 and 25.');
      return;
    }

    lastAge = age;
    lastDirection = direction;

    createBtn.disabled = true;
    createBtn.innerHTML = '<span class="spinner"></span> Minting...';
    announce('Minting sandbox credentials...');

    try {
      var response = await fetch('/playground/api/create-environment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ age: age, direction: direction }),
      });

      var data = await response.json();

      if (!response.ok) {
        if (response.status === 429) {
          var msg = 'Rate limit reached: 5 mints per hour.';
          if (data.resetsAt) {
            var diffSec = Math.max(0, Math.floor(data.resetsAt - Date.now() / 1000));
            if (diffSec > 60) {
              var mins = Math.ceil(diffSec / 60);
              msg += ' Retry in about ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.';
            } else if (diffSec > 0) {
              msg += ' Retry in about ' + diffSec + ' seconds.';
            }
          }
          showVerifierFormError(msg);
        } else {
          showVerifierFormError(data.error || 'Mint failed. Check your connection and try again.');
        }
        announce('Mint failed');
        return;
      }

      var bundle = {
        publicKey: data.publicKey,
        clientId: data.clientId,
        hmacSecret: data.hmacSecret,
        apiKey: data.apiKey,
        registeredOrigin: data.registeredOrigin || data.registered_origin,
        baseUrl: data.baseUrl || data.base_url,
        mintedAt: data.mintedAt || nowSeconds(),
        expiresAt: data.expiresAt,
        age: age,
        direction: direction,
        codeSnippets: data.codeSnippets,
      };

      renderVerifierCredentials(bundle);
      persistVerifier(bundle);

      announce('Credentials minted. Pick a mode and copy the snippet.');
      var heading = document.getElementById('results-heading');
      if (heading) heading.focus();
    } catch (err) {
      showVerifierFormError('Network error. Check your connection and try again.');
      announce('Network error');
    } finally {
      createBtn.disabled = false;
      createBtn.textContent = 'Mint sandbox credentials';
    }
  });

  function startVerifierFormFresh() {
    clearVerifierErrors();
    lastCredentials = null;
    if (lastAge >= 5 && lastAge <= 25) {
      var option = ageSelect.querySelector('option[value="' + lastAge + '"]');
      if (option) {
        ageSelect.value = String(lastAge);
        customAgeWrapper.style.display = 'none';
      } else {
        ageSelect.value = 'custom';
        customAgeWrapper.style.display = 'block';
        ageInput.value = String(lastAge);
      }
    }
    var radios = document.querySelectorAll('input[name="direction"]');
    radios.forEach(function (r) { r.checked = r.value === lastDirection; });
    var toggleOptions = document.querySelectorAll('#role-panel-verifier .demo-toggle__option');
    toggleOptions.forEach(function (opt) {
      var radio = opt.querySelector('input[type="radio"]');
      opt.classList.toggle('demo-toggle__option--active', !!(radio && radio.checked));
    });
    showVerifierSection('form');
    ageSelect.focus();
  }

  resetBtn.addEventListener('click', function () {
    clearVerifierFromStorage();
    startVerifierFormFresh();
  });

  if (verifierRemintBtn) {
    verifierRemintBtn.addEventListener('click', function () {
      clearVerifierFromStorage();
      startVerifierFormFresh();
    });
  }

  ageSelect.addEventListener('change', function () {
    if (ageSelect.value === 'custom') {
      customAgeWrapper.style.display = 'block';
      ageInput.focus();
    } else {
      customAgeWrapper.style.display = 'none';
    }
  });

 // ==========================================================================
 // Issuer panel
 // ==========================================================================

  function showIssuerSection(name) {
    sectionIssuerForm.classList.toggle('section-hidden', name !== 'form');
    sectionIssuerResults.classList.toggle('section-hidden', name !== 'results');
  }

  function clearIssuerErrors() {
    issuerFormAlert.style.display = 'none';
    issuerFormAlert.textContent = '';
    issuerLabelError.textContent = '';
    issuerLabelError.style.display = 'none';
    issuerLabelInput.removeAttribute('aria-invalid');
  }

  function showIssuerFormError(message) {
    issuerFormAlert.textContent = message;
    issuerFormAlert.style.display = 'block';
  }

  function showIssuerLabelError(message) {
    issuerLabelError.textContent = message;
    issuerLabelError.style.display = 'block';
    issuerLabelInput.setAttribute('aria-invalid', 'true');
    issuerLabelInput.focus();
  }

  function validateIssuerLabel(label) {
    if (typeof label !== 'string') return 'Issuer label is required.';
    var trimmed = label.trim();
    if (trimmed.length < 1) return 'Issuer label is required.';
    if (trimmed.length > 64) return 'Issuer label must be 64 characters or fewer.';
 // Printable ASCII only (0x20 to 0x7E). Wallet attestation prompts
 // render this string and we don't want surprises with smart quotes
 // or RTL controls in a sandbox UI string.
    if (!/^[\x20-\x7E]+$/.test(trimmed)) {
      return 'Issuer label must use plain ASCII characters only.';
    }
    return null;
  }

  function buildIssuerSnippets(bundle) {
    var clientId = bundle.clientId || '';
    var hmacSecret = bundle.hmacSecret || '';
    var baseUrl = bundle.baseUrl || 'https://sandbox-issuer.provii.app';

    var nodejs = ''
      + '// Request a signed attestation from Provii provii-issuer with your minted creds.\n'
      + '// Mirrors provii-demos/backends/issuer/nodejs/src/index.ts.\n'
      + 'import { createHmac, randomBytes } from "node:crypto";\n'
      + '\n'
      + 'const CLIENT_ID = "' + clientId + '";\n'
      + 'const HMAC_SECRET_B64URL = "' + hmacSecret + '";\n'
      + 'const ISSUER_API_URL = "' + baseUrl + '";\n'
      + '\n'
      + 'function b64urlDecode(s) {\n'
      + '  s = s.replace(/-/g, "+").replace(/_/g, "/");\n'
      + '  while (s.length % 4) s += "=";\n'
      + '  return Buffer.from(s, "base64");\n'
      + '}\n'
      + '\n'
      + 'async function createAttestation(dobDays) {\n'
      + '  const ts = Math.floor(Date.now() / 1000);\n'
      + '  const nonce = randomBytes(32).toString("hex");\n'
      + '  const canonicalJson =\n'
      + '    `{"dob_days":${dobDays},"authorizer":{"format":"client","key_id":"${CLIENT_ID}","timestamp":${ts}}}`;\n'
      + '  const message = `${ts}:POST:/v1/attestation/create:${canonicalJson}:${nonce}`;\n'
      + '  const hmac = createHmac("sha256", b64urlDecode(HMAC_SECRET_B64URL))\n'
      + '    .update(message)\n'
      + '    .digest("hex");\n'
      + '  const body = JSON.stringify({\n'
      + '    dob_days: dobDays,\n'
      + '    authorizer: { format: "client", keyId: CLIENT_ID, timestamp: ts, hmac, nonce },\n'
      + '  });\n'
      + '  const res = await fetch(`${ISSUER_API_URL}/v1/attestation/create`, {\n'
      + '    method: "POST",\n'
      + '    headers: { "Content-Type": "application/json" },\n'
      + '    body,\n'
      + '  });\n'
      + '  if (!res.ok) throw new Error(`provii-issuer ${res.status}: ${await res.text()}`);\n'
      + '  return res.json();\n'
      + '}\n'
      + '\n'
      + 'createAttestation(7000).then(console.log);\n';

    var go = ''
      + '// Request a signed attestation from Provii provii-issuer with your minted creds.\n'
      + 'package main\n'
      + '\n'
      + 'import (\n'
      + '    "bytes"\n'
      + '    "crypto/hmac"\n'
      + '    "crypto/rand"\n'
      + '    "crypto/sha256"\n'
      + '    "encoding/base64"\n'
      + '    "encoding/hex"\n'
      + '    "encoding/json"\n'
      + '    "fmt"\n'
      + '    "io"\n'
      + '    "net/http"\n'
      + '    "time"\n'
      + ')\n'
      + '\n'
      + 'const (\n'
      + '    clientID         = "' + clientId + '"\n'
      + '    hmacSecretB64Url = "' + hmacSecret + '"\n'
      + '    issuerAPIURL     = "' + baseUrl + '"\n'
      + ')\n'
      + '\n'
      + 'func main() {\n'
      + '    ts := time.Now().Unix()\n'
      + '    nonceBytes := make([]byte, 32)\n'
      + '    if _, err := rand.Read(nonceBytes); err != nil {\n'
      + '        panic(err)\n'
      + '    }\n'
      + '    nonce := hex.EncodeToString(nonceBytes)\n'
      + '\n'
      + '    dobDays := 7000\n'
      + '    canonical := fmt.Sprintf(\n'
      + '        `{"dob_days":%d,"authorizer":{"format":"client","key_id":"%s","timestamp":%d}}`,\n'
      + '        dobDays, clientID, ts,\n'
      + '    )\n'
      + '    message := fmt.Sprintf("%d:POST:/v1/attestation/create:%s:%s", ts, canonical, nonce)\n'
      + '\n'
      + '    secret, err := base64.RawURLEncoding.DecodeString(hmacSecretB64Url)\n'
      + '    if err != nil {\n'
      + '        panic(err)\n'
      + '    }\n'
      + '    mac := hmac.New(sha256.New, secret)\n'
      + '    mac.Write([]byte(message))\n'
      + '    sig := hex.EncodeToString(mac.Sum(nil))\n'
      + '\n'
      + '    body, _ := json.Marshal(map[string]interface{}{\n'
      + '        "dob_days": dobDays,\n'
      + '        "authorizer": map[string]interface{}{\n'
      + '            "format":    "client",\n'
      + '            "keyId":     clientID,\n'
      + '            "timestamp": ts,\n'
      + '            "hmac":      sig,\n'
      + '            "nonce":     nonce,\n'
      + '        },\n'
      + '    })\n'
      + '    res, err := http.Post(issuerAPIURL+"/v1/attestation/create", "application/json", bytes.NewReader(body))\n'
      + '    if err != nil {\n'
      + '        panic(err)\n'
      + '    }\n'
      + '    defer res.Body.Close()\n'
      + '    out, _ := io.ReadAll(res.Body)\n'
      + '    fmt.Printf("status=%d body=%s\\n", res.StatusCode, out)\n'
      + '}\n';

    var python = ''
      + '# Request a signed attestation from Provii provii-issuer with your minted creds.\n'
      + '# pip install requests\n'
      + 'import base64, hashlib, hmac, json, secrets, time\n'
      + 'import requests\n'
      + '\n'
      + 'CLIENT_ID = "' + clientId + '"\n'
      + 'HMAC_SECRET_B64URL = "' + hmacSecret + '"\n'
      + 'ISSUER_API_URL = "' + baseUrl + '"\n'
      + '\n'
      + 'def b64url_decode(s: str) -> bytes:\n'
      + '    pad = "=" * (-len(s) % 4)\n'
      + '    return base64.urlsafe_b64decode(s + pad)\n'
      + '\n'
      + 'def create_attestation(dob_days: int):\n'
      + '    ts = int(time.time())\n'
      + '    nonce = secrets.token_hex(32)\n'
      + '    canonical = (\n'
      + '        f\'{{"dob_days":{dob_days},\'\n'
      + '        f\'"authorizer":{{"format":"client","key_id":"{CLIENT_ID}","timestamp":{ts}}}}}\'\n'
      + '    )\n'
      + '    message = f"{ts}:POST:/v1/attestation/create:{canonical}:{nonce}"\n'
      + '    sig = hmac.new(b64url_decode(HMAC_SECRET_B64URL), message.encode(), hashlib.sha256).hexdigest()\n'
      + '    body = {\n'
      + '        "dob_days": dob_days,\n'
      + '        "authorizer": {\n'
      + '            "format": "client",\n'
      + '            "keyId": CLIENT_ID,\n'
      + '            "timestamp": ts,\n'
      + '            "hmac": sig,\n'
      + '            "nonce": nonce,\n'
      + '        },\n'
      + '    }\n'
      + '    r = requests.post(\n'
      + '        f"{ISSUER_API_URL}/v1/attestation/create",\n'
      + '        json=body,\n'
      + '        headers={"Content-Type": "application/json"},\n'
      + '        timeout=15,\n'
      + '    )\n'
      + '    r.raise_for_status()\n'
      + '    return r.json()\n'
      + '\n'
      + 'print(create_attestation(7000))\n';

 // cURL canonical message must be precomputed; we leave a shell skeleton
 // that mirrors how the demo backends prepare the HMAC. Sandbox-only,
 // dev-readable, no secrets shipped to a browser.
    var curl = ''
      + '# Request a signed attestation from Provii provii-issuer with your minted creds.\n'
      + '# Requires: openssl, jq. Replace 7000 with your dob_days value.\n'
      + 'CLIENT_ID="' + clientId + '"\n'
      + 'HMAC_SECRET_B64URL="' + hmacSecret + '"\n'
      + 'ISSUER_API_URL="' + baseUrl + '"\n'
      + 'DOB_DAYS=7000\n'
      + 'TS=$(date +%s)\n'
      + 'NONCE=$(openssl rand -hex 32)\n'
      + '\n'
      + '# decode the base64url HMAC secret to raw bytes. macOS base64 -d is\n'
      + '# strict: it silently truncates the trailing 4-char group when the\n'
      + '# input lacks padding, producing 30 bytes instead of 32 and a\n'
      + '# ciphertext-correct-but-key-wrong HMAC. The awk step adds = padding\n'
      + '# until the length is a multiple of 4.\n'
      + 'HMAC_SECRET_PADDED=$(printf "%s" "$HMAC_SECRET_B64URL" | tr "_-" "/+" \\\n'
      + '  | awk \'{ l=length($0); for (i=0; i<(4-l%4)%4; i++) $0=$0"="; print }\')\n'
      + 'HMAC_SECRET_HEX=$(printf "%s" "$HMAC_SECRET_PADDED" | base64 -d | xxd -p -c 256)\n'
      + '\n'
      + 'CANONICAL=$(printf \'{"dob_days":%d,"authorizer":{"format":"client","key_id":"%s","timestamp":%d}}\' "$DOB_DAYS" "$CLIENT_ID" "$TS")\n'
      + 'MESSAGE="${TS}:POST:/v1/attestation/create:${CANONICAL}:${NONCE}"\n'
      + 'HMAC=$(printf "%s" "$MESSAGE" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$HMAC_SECRET_HEX" | awk \'{print $2}\')\n'
      + '\n'
      + 'BODY=$(jq -nc --argjson dob "$DOB_DAYS" --arg cid "$CLIENT_ID" --argjson ts "$TS" --arg hmac "$HMAC" --arg nonce "$NONCE" \\\n'
      + '  \'{dob_days:$dob, authorizer:{format:"client", keyId:$cid, timestamp:$ts, hmac:$hmac, nonce:$nonce}}\')\n'
      + '\n'
      + 'curl -sS -X POST "$ISSUER_API_URL/v1/attestation/create" \\\n'
      + '  -H "Content-Type: application/json" \\\n'
      + '  -d "$BODY"\n';

    return { nodejs: nodejs, go: go, python: python, curl: curl };
  }

  function renderIssuerCredentials(bundle) {
    issuerCredClientId.textContent = bundle.clientId || '';
    issuerCredHmacSecret.textContent = bundle.hmacSecret || '';
    issuerCredKid.textContent = bundle.kid || '';
    issuerCredBaseUrl.textContent = bundle.baseUrl || '';
    issuerCredExpires.textContent = formatExpiresAbsolute(bundle.expiresAt);

    lastIssuerCredentials = {
      clientId: bundle.clientId || '',
      hmacSecret: bundle.hmacSecret || '',
      kid: bundle.kid || '',
      baseUrl: bundle.baseUrl || '',
      expiresAt: bundle.expiresAt || null,
    };

    var snippets = buildIssuerSnippets(bundle);
    Object.keys(issuerSnippetTargets).forEach(function (lang) {
      var target = issuerSnippetTargets[lang];
      if (target) target.textContent = snippets[lang] || '';
    });

    showIssuerSection('results');
    updateIssuerExpiryUi(bundle.expiresAt);
  }

  function buildIssuerEnvVarBlock(creds) {
    var lines = [];
    if (creds.clientId) lines.push('PROVII_CLIENT_ID=' + creds.clientId);
    if (creds.hmacSecret) lines.push('PROVII_HMAC_SECRET=' + creds.hmacSecret);
    if (creds.kid) lines.push('PROVII_ISSUER_KID=' + creds.kid);
    if (creds.baseUrl) lines.push('PROVII_ISSUER_API_URL=' + creds.baseUrl);
    if (creds.expiresAt) lines.push('PROVII_EXPIRES_AT=' + creds.expiresAt);
    return lines.join('\n');
  }

  function updateIssuerExpiryUi(expiresAt) {
    if (!expiresAt) {
      issuerExpiryWarning.hidden = true;
      issuerTimeRemaining.textContent = '';
      return;
    }
    var remaining = expiresAt - nowSeconds();
    if (remaining <= 0) {
      issuerExpiryWarning.hidden = false;
      issuerExpiryRelative.textContent = 'Expired ' + formatDuration(-remaining) + ' ago.';
      issuerTimeRemaining.textContent = 'Expired.';
    } else if (remaining <= EXPIRY_WARNING_WINDOW_SECONDS) {
      issuerExpiryWarning.hidden = false;
      issuerExpiryRelative.textContent = 'Expires in ' + formatDuration(remaining) + '.';
      issuerTimeRemaining.textContent = 'Expires in ' + formatDuration(remaining) + ' (' + formatExpiresAbsolute(expiresAt) + ').';
    } else {
      issuerExpiryWarning.hidden = true;
      issuerTimeRemaining.textContent = 'Expires in ' + formatDuration(remaining) + ' (' + formatExpiresAbsolute(expiresAt) + ').';
    }
  }

  function clearIssuerFromStorage() {
    safeClearStorage(ISSUER_STORAGE_KEY);
  }

  function persistIssuer(bundle) {
    safeWriteStorage(ISSUER_STORAGE_KEY, {
      clientId: bundle.clientId || '',
      hmacSecret: bundle.hmacSecret || '',
      kid: bundle.kid || '',
      baseUrl: bundle.baseUrl || '',
      mintedAt: bundle.mintedAt || nowSeconds(),
      expiresAt: bundle.expiresAt || null,
    });
  }

  function rehydrateIssuer() {
    var stored = safeReadStorage(ISSUER_STORAGE_KEY);
    if (!stored) return false;
    if (stored.expiresAt && stored.expiresAt <= nowSeconds()) {
      clearIssuerFromStorage();
      return false;
    }
    renderIssuerCredentials(stored);
    return true;
  }

  function startIssuerFormFresh() {
    clearIssuerErrors();
    lastIssuerCredentials = null;
    issuerLabelInput.value = '';
    showIssuerSection('form');
    issuerLabelInput.focus();
  }

  issuerCreateBtn.addEventListener('click', async function () {
    clearIssuerErrors();

    var label = (issuerLabelInput.value || '').trim();
    var labelErr = validateIssuerLabel(label);
    if (labelErr) {
      showIssuerLabelError(labelErr);
      return;
    }

    issuerCreateBtn.disabled = true;
    issuerCreateBtn.innerHTML = '<span class="spinner"></span> Minting...';
    announce('Minting issuer credentials...');

    try {
      var response = await fetch('/playground/api/create-issuer-environment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issuer_label: label }),
      });

      var data;
      try {
        data = await response.json();
      } catch (_e) {
        data = {};
      }

      if (!response.ok) {
        if (response.status === 404) {
 // Wave B endpoint not deployed yet; surface a clear message rather
 // than the generic "Mint failed" string. Frontend ships ahead of
 // backend so devs hitting this in CI need to know why.
          showIssuerFormError(
            'Issuer mint endpoint is not yet deployed on this environment. ' +
            'See the credential-paths plan, Wave B.',
          );
        } else if (response.status === 429) {
          var msg = 'Rate limit reached: 5 mints per hour.';
          if (data.resetsAt) {
            var diffSec = Math.max(0, Math.floor(data.resetsAt - Date.now() / 1000));
            if (diffSec > 60) {
              var mins = Math.ceil(diffSec / 60);
              msg += ' Retry in about ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.';
            } else if (diffSec > 0) {
              msg += ' Retry in about ' + diffSec + ' seconds.';
            }
          }
          showIssuerFormError(msg);
        } else {
          showIssuerFormError(data.error || 'Mint failed. Check your connection and try again.');
        }
        announce('Issuer mint failed');
        return;
      }

 // Response shape: client_id, hmac_secret, kid, expires_at, base_url, minted_at.
      var bundle = {
        clientId: data.client_id,
        hmacSecret: data.hmac_secret,
        kid: data.kid,
        baseUrl: data.base_url,
        mintedAt: data.minted_at || nowSeconds(),
        expiresAt: data.expires_at,
      };
      if (!bundle.clientId || !bundle.hmacSecret) {
        showIssuerFormError('Mint response missing required fields. Re-try in a moment.');
        announce('Issuer mint failed');
        return;
      }

      renderIssuerCredentials(bundle);
      persistIssuer(bundle);

      announce('Issuer credentials minted.');
      if (issuerCredHeading) issuerCredHeading.focus();
    } catch (err) {
      showIssuerFormError('Network error. Check your connection and try again.');
      announce('Network error');
    } finally {
      issuerCreateBtn.disabled = false;
      issuerCreateBtn.textContent = 'Mint issuer credentials';
    }
  });

  if (issuerResetBtn) {
    issuerResetBtn.addEventListener('click', function () {
      clearIssuerFromStorage();
      startIssuerFormFresh();
    });
  }

  if (issuerRemintBtn) {
    issuerRemintBtn.addEventListener('click', function () {
      clearIssuerFromStorage();
      startIssuerFormFresh();
    });
  }

 // ==========================================================================
 // Cross-cutting: clipboard, tab keyboard navigation, copy-all
 // ==========================================================================

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-copy');
    if (!btn) return;
    var targetId = btn.getAttribute('data-copy-target');
    var targetEl = document.getElementById(targetId);
    if (!targetEl) return;
    var text = targetEl.textContent || '';
    navigator.clipboard.writeText(text).then(function () {
      var original = btn.textContent;
      btn.textContent = 'Copied!';
      announce('Copied to clipboard');
      setTimeout(function () { btn.textContent = original; }, 2000);
    }).catch(function () {
      announce('Clipboard blocked. Select and copy manually.');
    });
  });

  if (copyAllBtn) {
    copyAllBtn.addEventListener('click', function () {
      if (!lastCredentials) {
        announce('No credentials to copy. Mint a sandbox environment first.');
        return;
      }
      var block = buildEnvVarBlock(lastCredentials, getActiveMode());
      navigator.clipboard.writeText(block).then(function () {
        var original = copyAllBtn.textContent;
        copyAllBtn.textContent = 'Copied all!';
        if (copyAllStatus) {
          copyAllStatus.textContent = 'Shell env vars copied.';
          copyAllStatus.setAttribute('data-visible', 'true');
          copyAllStatus.setAttribute('aria-hidden', 'false');
        }
        announce('All credentials copied to clipboard as shell env vars');
        setTimeout(function () {
          copyAllBtn.textContent = original;
          if (copyAllStatus) {
            copyAllStatus.setAttribute('data-visible', 'false');
            copyAllStatus.setAttribute('aria-hidden', 'true');
          }
        }, 2000);
      }).catch(function () {
        announce('Clipboard blocked. Select and copy manually.');
      });
    });
  }

  if (issuerCopyAllBtn) {
    issuerCopyAllBtn.addEventListener('click', function () {
      if (!lastIssuerCredentials) {
        announce('No issuer credentials to copy. Mint a credential first.');
        return;
      }
      var block = buildIssuerEnvVarBlock(lastIssuerCredentials);
      navigator.clipboard.writeText(block).then(function () {
        var original = issuerCopyAllBtn.textContent;
        issuerCopyAllBtn.textContent = 'Copied all!';
        if (issuerCopyAllStatus) {
          issuerCopyAllStatus.textContent = 'Shell env vars copied.';
          issuerCopyAllStatus.setAttribute('data-visible', 'true');
          issuerCopyAllStatus.setAttribute('aria-hidden', 'false');
        }
        announce('All issuer credentials copied to clipboard as shell env vars');
        setTimeout(function () {
          issuerCopyAllBtn.textContent = original;
          if (issuerCopyAllStatus) {
            issuerCopyAllStatus.setAttribute('data-visible', 'false');
            issuerCopyAllStatus.setAttribute('aria-hidden', 'true');
          }
        }, 2000);
      }).catch(function () {
        announce('Clipboard blocked. Select and copy manually.');
      });
    });
  }

  /**
 * Wire keyboard + click navigation for a tablist. `tabs` may be the mode
 * picker, a per-mode language strip, or the issuer language strip.
   */
  function bindTabList(tabs, onActivate) {
    var tabList = Array.from(tabs);
    if (tabList.length === 0) return;
    tabList.forEach(function (tab) {
      tab.addEventListener('click', function () { onActivate(tab); });
      tab.addEventListener('keydown', function (e) {
        var index = tabList.indexOf(e.target);
        if (index < 0) return;
        var nextIndex = -1;
        if (e.key === 'ArrowRight') nextIndex = (index + 1) % tabList.length;
        else if (e.key === 'ArrowLeft') nextIndex = (index - 1 + tabList.length) % tabList.length;
        else if (e.key === 'Home') nextIndex = 0;
        else if (e.key === 'End') nextIndex = tabList.length - 1;
        if (nextIndex >= 0) {
          e.preventDefault();
          tabList[nextIndex].focus();
          onActivate(tabList[nextIndex]);
        }
      });
    });
  }

  bindTabList(modeTabs, function (tab) {
    var mode = tab.getAttribute('data-mode') || 'simple';
    activateMode(mode);
  });

  document.querySelectorAll('.pg-inline-link[data-target-mode]').forEach(function (link) {
    link.addEventListener('click', function () {
      var targetMode = link.getAttribute('data-target-mode');
      if (!targetMode || VALID_MODES.indexOf(targetMode) === -1) return;
      activateMode(targetMode);
      var targetTab = document.getElementById('mode-tab-' + targetMode);
      if (targetTab) targetTab.focus();
    });
  });

 // Per-mode language tab strips (verifier panel).
  var codeTabsByMode = { simple: [], expert: [], mobile: [] };
  document.querySelectorAll('.code-tab').forEach(function (tab) {
    var mode = tab.getAttribute('data-mode');
    if (codeTabsByMode[mode]) codeTabsByMode[mode].push(tab);
  });
  Object.keys(codeTabsByMode).forEach(function (mode) {
    var tabs = codeTabsByMode[mode];
    bindTabList(tabs, function (tab) {
      tabs.forEach(function (t) {
        var isActive = t === tab;
        t.setAttribute('aria-selected', isActive ? 'true' : 'false');
        t.setAttribute('tabindex', isActive ? '0' : '-1');
        t.classList.toggle('demo-tab--active', isActive);
        var panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel) panel.setAttribute('aria-hidden', isActive ? 'false' : 'true');
      });
    });
  });

 // Issuer language tab strip.
  var issuerCodeTabs = Array.from(document.querySelectorAll('.issuer-code-tab'));
  bindTabList(issuerCodeTabs, function (tab) {
    issuerCodeTabs.forEach(function (t) {
      var isActive = t === tab;
      t.setAttribute('aria-selected', isActive ? 'true' : 'false');
      t.setAttribute('tabindex', isActive ? '0' : '-1');
      t.classList.toggle('demo-tab--active', isActive);
      var panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.setAttribute('aria-hidden', isActive ? 'false' : 'true');
    });
  });

 // ==========================================================================
 // Initial render
 // ==========================================================================

  bindRoleTabs();
  setActiveRole(getRoleFromHash(), { updateHash: false });

 // Apply persisted mode for the verifier panel so the credential rows hide
 // appropriately even before the first mint completes.
  activateMode(readPersistedMode());

 // Try to rehydrate each panel from localStorage. If a fresh bundle exists
 // and isn't expired, the user lands on the cred summary directly.
  var verifierRehydrated = rehydrateVerifier();
  if (!verifierRehydrated) {
    showVerifierSection('form');
  }
  var issuerRehydrated = rehydrateIssuer();
  if (!issuerRehydrated) {
    showIssuerSection('form');
  }

 // Tick once a minute so the time-remaining label and the expiry warning
 // stay current without eating CPU. Sub-minute precision isn't useful for
 // hour-scale TTLs.
  timeRemainingInterval = window.setInterval(function () {
    var verifierStored = safeReadStorage(VERIFIER_STORAGE_KEY);
    if (verifierStored && verifierStored.expiresAt) {
      updateVerifierExpiryUi(verifierStored.expiresAt);
    }
    var issuerStored = safeReadStorage(ISSUER_STORAGE_KEY);
    if (issuerStored && issuerStored.expiresAt) {
      updateIssuerExpiryUi(issuerStored.expiresAt);
    }
  }, 60 * 1000);
})();
