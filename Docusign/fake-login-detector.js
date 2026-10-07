// Fake Google / Microsoft 365 login page detector.
// Runs on all http/https pages (top frame only). If the page imitates the real
// Google or Microsoft sign-in flow but is NOT hosted on a trusted login origin,
// a full-page blocking overlay is shown naming the suspicious hostname.
//
// Origin tiers (trusted / tenant-hosted / known-abuse / login-CDN assets) live
// in trusted-origins.js, which the manifest loads before this file.

// Cheap gate: only pages containing credential-shaped inputs get scanned at all.
// Google's real flow shows the email/identifier page before any password field,
// so email and brand-specific identifier inputs are part of the gate.
const LOGIN_INPUT_SELECTOR = [
    'input[type="password"]',
    'input[type="email"]',
    'input[name="identifier"]', '#identifierId',   // Google sign-in fingerprints
    'input[name="loginfmt"]', '#i0116'             // Microsoft sign-in fingerprints
].join(',');

// Scan subresource references (not loads — attribute values are enough, and
// kits hotlink the real CDNs) for login-asset hosts.
function pageReferencesAssetHosts(suffixes) {
    const els = document.querySelectorAll('img[src], script[src], link[href], source[src], iframe[src]');
    for (const el of els) {
        const raw = el.getAttribute('src') || el.getAttribute('href');
        if (!raw) continue;
        let host;
        try {
            host = new URL(raw, location.href).hostname.toLowerCase();
        } catch (e) {
            continue;
        }
        if (host === location.hostname) continue;
        if (suffixes.some(d => hostMatchesSuffix(host, d))) return true;
    }
    return false;
}

// --- THE RULES ENGINE ---
// Each signal: { weight, test(text, title) }. A brand triggers when the summed
// score is >= SCORE_THRESHOLD AND at least one weight-3 (strong) signal matched.
// Strong signals are brand-exclusive fingerprints that pixel-perfect clones and
// AiTM reverse-proxy kits (evilginx — they serve the real HTML) carry verbatim;
// weak signals alone (e.g. a "Sign in with Google" button) never trigger.
const SCORE_THRESHOLD = 4;
const STRONG_WEIGHT = 3;

const BRAND_RULES = [
    {
        brandName: 'Google',
        realHost: 'accounts.google.com',
        signals: [
            { weight: 3, test: (t) => t.includes('use your google account') },
            { weight: 3, test: () => !!document.querySelector('input[name="identifier"], #identifierId') },
            { weight: 3, test: (t, title) => /^sign in\b.*google accounts$/.test(title) },
            { weight: 2, test: (t) => t.includes('to continue to') && t.includes('google') },
            // Page hotlinks Google sign-in asset hosts. Not weight 3: unlike
            // Microsoft's dedicated login CDNs, gstatic hosts have some legit
            // third-party reach, so corroboration is required.
            { weight: 2, test: () => pageReferencesAssetHosts(GOOGLE_LOGIN_ASSET_SUFFIXES) },
            { weight: 1, test: () => !!document.querySelector('img[alt="Google" i], [aria-label="Google" i]') },
            { weight: 1, test: (t) => t.includes('forgot email?') },
            { weight: 1, test: (t) => t.includes('sign in') && !!document.querySelector('input[type="email"], input[name="identifier"]') }
        ]
    },
    {
        brandName: 'Microsoft',
        realHost: 'login.microsoftonline.com',
        signals: [
            { weight: 3, test: () => !!document.querySelector('input[name="loginfmt"], #i0116') },
            { weight: 3, test: (t) => t.includes('sign in to continue to') || t.includes('no account? create one!') },
            // Page hotlinks Microsoft's login-UI CDNs (aadcdn/logincdn/acctcdn).
            // Nothing legitimate outside Microsoft login pages references these —
            // this is the signal that catches AiTM kits serving the real HTML.
            { weight: 3, test: () => pageReferencesAssetHosts(MS_LOGIN_ASSET_SUFFIXES) },
            { weight: 2, test: (t, title) => title === 'sign in to your account' },
            { weight: 2, test: (t) => t.includes("can't access your account?") },
            { weight: 1, test: () => !!document.querySelector('img[alt="Microsoft" i], [aria-label="Microsoft" i]') },
            { weight: 1, test: (t) => t.includes('sign in') && !!document.querySelector('input[type="email"], input[name="loginfmt"]') }
        ]
    }
];

// Curly apostrophes are normalized because real Google/Microsoft copy uses them
// and clones copy the text verbatim.
function normalizeText(s) {
    return (s || '').toLowerCase().replace(/[‘’]/g, "'").replace(/\s+/g, ' ');
}

let overlayEl = null;
let overlayShown = false;
let userProceeded = false;
let scanTimer = null;

function buildOverlay(rule) {
    const overlay = document.createElement('div');
    overlay.id = 'ysd7-login-blocker';
    overlay.style.cssText = [
        'position: fixed',
        'top: 0', 'left: 0', 'right: 0', 'bottom: 0',
        'z-index: 2147483647',
        'background: rgba(130, 10, 10, 0.97)',
        'color: #ffffff',
        'display: flex',
        'flex-direction: column',
        'align-items: center',
        'justify-content: center',
        'text-align: center',
        'padding: 40px',
        'font-family: Roboto, Arial, sans-serif'
    ].join(';');

    const heading = document.createElement('div');
    heading.style.cssText = 'font-size: 32px; font-weight: bold; margin-bottom: 20px;';
    heading.textContent = '⚠️ Suspected fake ' + rule.brandName + ' sign-in page';
    overlay.appendChild(heading);

    const intro = document.createElement('div');
    intro.style.cssText = 'font-size: 17px; max-width: 640px; margin-bottom: 12px;';
    intro.textContent = 'This page imitates the real ' + rule.brandName + ' login but is actually hosted at:';
    overlay.appendChild(intro);

    const hostLine = document.createElement('div');
    hostLine.style.cssText = 'font-family: Consolas, monospace; font-size: 22px; font-weight: bold; background: rgba(0,0,0,0.35); padding: 10px 24px; border-radius: 6px; margin-bottom: 20px; word-break: break-all; max-width: 90%;';
    // Attacker-controlled value: textContent only, never HTML interpolation.
    hostLine.textContent = location.hostname;
    overlay.appendChild(hostLine);

    const body = document.createElement('div');
    body.style.cssText = 'font-size: 15px; max-width: 640px; line-height: 1.5; margin-bottom: 30px;';
    body.textContent = 'The real ' + rule.brandName + ' sign-in only happens on ' + rule.realHost + '. ' +
        'Do not enter your email or password on this page. ' +
        'If you believe this warning is an error, contact YSD7 IT.';
    overlay.appendChild(body);

    const leaveBtn = document.createElement('button');
    leaveBtn.style.cssText = 'font-size: 18px; font-weight: bold; padding: 14px 40px; border: none; border-radius: 6px; background: #ffffff; color: #820a0a; cursor: pointer; font-family: inherit;';
    leaveBtn.textContent = 'Leave this page';
    leaveBtn.addEventListener('click', () => {
        leaveBtn.textContent = 'Leaving…';
        // history.back() is a silent no-op when there is no eligible entry
        // (Chrome prunes replaced/redirect entries, so history.length alone
        // can't be trusted). Try it, and if this page hasn't started unloading
        // shortly after, force-navigate to a blank page instead.
        setTimeout(() => location.replace('about:blank'), 400);
        if (history.length > 1) {
            history.back();
        }
    });
    overlay.appendChild(leaveBtn);

    const proceed = document.createElement('a');
    proceed.style.cssText = 'font-size: 12px; opacity: 0.7; color: #ffffff; text-decoration: underline; margin-top: 28px; cursor: pointer;';
    proceed.textContent = 'Proceed anyway (not recommended)';
    proceed.addEventListener('click', () => {
        userProceeded = true;
        overlay.remove();
        document.documentElement.style.overflow = '';
    });
    overlay.appendChild(proceed);

    return overlay;
}

function showOverlay(rule) {
    overlayEl = buildOverlay(rule);
    // Appended to documentElement, not body, so a phish script replacing the
    // body's contents does not take the overlay with it.
    document.documentElement.appendChild(overlayEl);
    document.documentElement.style.overflow = 'hidden';
    overlayShown = true;
}

// Deliberately modest tamper resistance: re-append if a generic phish kit removes
// the overlay. Non-goals: closed shadow roots, animation-frame watchdogs — a kit
// written against this specific extension wins regardless; the job is defeating
// generic kits and making the user pause.
function reinjectOverlayIfRemoved() {
    if (overlayShown && !userProceeded && !document.getElementById('ysd7-login-blocker')) {
        document.documentElement.appendChild(overlayEl);
        document.documentElement.style.overflow = 'hidden';
    }
}

function scanPage() {
    if (userProceeded) return;
    if (overlayShown) {
        reinjectOverlayIfRemoved();
        return;
    }
    if (!document.querySelector(LOGIN_INPUT_SELECTOR)) return;

    const text = normalizeText(document.body ? document.body.innerText : '');
    const title = normalizeText(document.title);

    // Hosts like *.sharepoint.com, *.blob.core.windows.net, *.firebaseapp.com
    // never legitimately render a vendor credential prompt: score them up, and
    // let a password field there satisfy the strong-signal requirement so a
    // brand-styled password form on an abuse host triggers without needing a
    // copied markup fingerprint.
    const abuseHost = isKnownAbuseHost(location.hostname);
    const abuseStrong = abuseHost && !!document.querySelector('input[type="password"]');

    for (const rule of BRAND_RULES) {
        let score = abuseHost ? 2 : 0;
        let hasStrong = abuseStrong;
        for (const signal of rule.signals) {
            let matched = false;
            try {
                matched = !!signal.test(text, title);
            } catch (e) {
                matched = false;
            }
            if (matched) {
                score += signal.weight;
                if (signal.weight >= STRONG_WEIGHT) hasStrong = true;
            }
        }
        if (score >= SCORE_THRESHOLD && hasStrong) {
            showOverlay(rule);
            return;
        }
    }
}

function scheduleScan() {
    if (userProceeded) return;
    if (overlayShown) {
        // Repair synchronously — debouncing here would hand a phish script a
        // half-second window with the overlay gone after each removal.
        reinjectOverlayIfRemoved();
        return;
    }
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scanPage, 500);
}

if (!isTrustedLoginHost(location.hostname)) {
    scanPage();
    // Catches phish kits that render their markup via JS after load; after a
    // detection, the same observer powers overlay re-injection.
    new MutationObserver(scheduleScan)
        .observe(document.documentElement, { childList: true, subtree: true });
}
