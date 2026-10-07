// Tiered origin lists for the fake-login detector. Loaded before
// fake-login-detector.js (see manifest content_scripts js order).
//
// Sources: Microsoft 365 URLs & IP ranges page (identity section, endpoint
// IDs 56/59) and Google's Workspace host-name allowlist article. Microsoft
// shuffles these periodically (*.cloud.microsoft migration) — future
// enhancement is serving this as remotely updatable JSON from the GitHub
// Pages repo so list changes don't require a repack.
//
// Matching is exact host or dot-boundary suffix ("h === d || h.endsWith('.'+d)").
// That inherently defeats the two classic tricks: prefix abuse
// ("login.microsoftonline.com.evil.net" does not END with a trusted suffix)
// and IDN homoglyphs (location.hostname reports punycode, so a Cyrillic-е
// "googlе.com" arrives as "xn--..." and matches nothing). A full Public
// Suffix List matcher is unnecessary for suffix allowlisting.

// Tier 1 — hosts where a real credential prompt can legitimately render
// (top-frame origins). Suffix entries cover their subdomains.
const TRUSTED_LOGIN_SUFFIXES = [
    // Microsoft — Entra ID / converged MSA
    'microsoftonline.com',        // login., loginex., login-us., device.login., ccs.login., passwordreset.
    'microsoftonline-p.com',      // legacy
    'microsoft.com',              // login., account., myaccount., mysignins., *.auth.microsoft.com
    'live.com',                   // login., account., signup.
    'microsoftazuread-sso.com',   // seamless SSO (no form, but legit)
    'msidentity.com',
    'msftidentity.com',
    'activedirectory.windowsazure.com',
    'office.com',
    'office365.com',
    'microsoft365.com',
    // Microsoft — sovereign / government clouds
    'microsoftonline.us',         // GCC High / DoD
    'auth.microsoft.us',
    'gov.us.microsoftonline.com',
    'login.chinacloudapi.cn',
    'partner.microsoftonline.cn',
    // NOTE: login.microsoftonline.de (Germany cloud) was retired — deliberately absent.
    // Google — google.com broadly (accounts., myaccount., admin., www.google.com
    // legacy /accounts/* and /a/<domain>/* paths). Known tradeoff: this also
    // trusts sites.google.com / docs.google.com, whose forms-based phish needs
    // different heuristics than login-clone detection (out of scope for v1.1).
    'google.com',
    'gstatic.com',                // raw asset host, never renders a form; harmless as top frame
    // District / org IdP. Entra home-realm discovery and Workspace SSO redirect
    // to the org's federation server — add the org IdP host here, not vendor lists.
    'ysd7.org'
];

const TRUSTED_LOGIN_EXACT = [
    'login.windows.net',          // legacy AAD, still live — exact only: the rest of
                                  // *.windows.net (blob storage, app service) is attacker-hostable
    'accounts.youtube.com'        // Google cookie-sync redirect hop, no form
];

// accounts.google.<ccTLD> CheckCookie hops: accounts.google.de, accounts.google.co.uk, ...
const TRUSTED_LOGIN_REGEX = [
    /^accounts\.google\.[a-z]{2,3}(\.[a-z]{2})?$/
];

// Tier 2 — Microsoft-hosted but tenant-named (Entra External ID / B2C).
// Anyone can create a tenant, so a real Microsoft-hosted page here can still
// be a phish; treated as "no overlay" (it IS Microsoft-served UI, and tenant
// legitimacy is not judgeable from page markup).
const TENANT_LOGIN_SUFFIXES = [
    'b2clogin.com',
    'ciamlogin.com'
];

// Tier 3 — hosts attackers love that are NEVER legitimate top-frame login
// pages. A brand-styled credential form on these scores extra.
const KNOWN_ABUSE_SUFFIXES = [
    'sharepoint.com',
    'onmicrosoft.com',
    'azurewebsites.net',
    'windows.net',                // *.blob.core.windows.net static-site phish
    'firebaseapp.com',
    'web.app',
    'storage.googleapis.com',
    'googleusercontent.com'
];

// Tier 4 — login-page asset/CDN hosts. Real sign-in pages load their assets
// from these; so do phishing kits that hotlink them. A non-trusted top frame
// pulling subresources from here is a strong phish signal.
// Microsoft's are exclusively login-UI CDNs — strong signal.
const MS_LOGIN_ASSET_SUFFIXES = [
    'aadcdn.msftauth.net',
    'aadcdn.msauth.net',
    'aadcdn.msftauthimages.net',
    'aadcdn.msauthimages.net',
    'logincdn.msauth.net',
    'logincdn.msftauth.net',
    'acctcdn.msauth.net',
    'acctcdn.msftauth.net',
    'secure.aadcdn.microsoftonline-p.com',
    'msauthimages.us',
    'msftauthimages.us'
];
// Google's sign-in assets come from gstatic hosts that legit third-party pages
// rarely reference directly — but fonts.gstatic.com / www.gstatic.com are
// everywhere (Google Fonts, reCAPTCHA) and are deliberately NOT listed.
// Weaker signal than Microsoft's dedicated login CDNs.
const GOOGLE_LOGIN_ASSET_SUFFIXES = [
    'ssl.gstatic.com',
    'accounts.gstatic.com',
    'accounts.youtube.com'
];

function hostMatchesSuffix(hostname, suffix) {
    return hostname === suffix || hostname.endsWith('.' + suffix);
}

function isTrustedLoginHost(hostname) {
    const h = hostname.toLowerCase();
    return TRUSTED_LOGIN_EXACT.includes(h) ||
        TRUSTED_LOGIN_SUFFIXES.some(d => hostMatchesSuffix(h, d)) ||
        TENANT_LOGIN_SUFFIXES.some(d => hostMatchesSuffix(h, d)) ||
        TRUSTED_LOGIN_REGEX.some(re => re.test(h));
}

function isKnownAbuseHost(hostname) {
    const h = hostname.toLowerCase();
    return KNOWN_ABUSE_SUFFIXES.some(d => hostMatchesSuffix(h, d));
}
