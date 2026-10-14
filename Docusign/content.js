// Target the universal message container
const GMAIL_MESSAGE_CONTAINER = '.h7';
const GMAIL_SENDER_ELEMENT = '.gD';
const GMAIL_SUBJECT_CLASS = '.hP';

// --- THE RULES ENGINE ---
const SECURITY_RULES = [
    {
        brandName: 'DocuSign',
        keywords: ['docusign'],
        contextKeywords: [],
        triggerSenders: [],
        safeSenders: ['@docusign.net', '@docusign.com', '@ysd7.org'],
        safeSharerDomains: [],
        requiresBodyMatch: []
    },
    {
        brandName: 'Google Drive',
        keywords: ['shared', 'invited you', 'item shared with you', 'request for access', 'document shared with you'],
        contextKeywords: [],
        triggerSenders: ['drive-shares-dm-noreply@google.com'],
        safeSenders: [],
        safeSharerDomains: ['@ysd7.org'],
        requiresBodyMatch: []
    },
    {
        brandName: 'Microsoft OneDrive/SharePoint',
        keywords: ['shared a file', 'shared a folder', 'sharepoint', 'onedrive'],
        contextKeywords: ['microsoft', 'sharepoint', 'onedrive', 'excel', 'word'],
        triggerSenders: [],
        safeSenders: ['@sharepointonline.com', '@microsoft.com', '@onmicrosoft.com', '@ysd7.org'],
        safeSharerDomains: [],
        requiresBodyMatch: ['@ysd7.org']
    },
    {
        brandName: 'Dropbox',
        keywords: ['shared a file', 'shared a folder', 'view file'],
        contextKeywords: ['dropbox'],
        triggerSenders: [],
        safeSenders: ['@dropbox.com', '@dropboxmail.com', '@ysd7.org'],
        safeSharerDomains: [],
        requiresBodyMatch: ['@ysd7.org']
    }
];

// Helper Function: Extract the true sharer from Gmail's hovercard attribute
function getTrueSharerEmail(msgElement) {
    const hoverElement = msgElement.querySelector('[data-hovercard-id]');
    if (hoverElement) {
        return hoverElement.getAttribute('data-hovercard-id').toLowerCase();
    }

    const rawHtml = msgElement.innerHTML || '';
    const match = rawHtml.match(/data-hovercard-id="([^"]+)"/i);
    if (match) {
        return match[1].toLowerCase();
    }

    return null;
}

const observer = new MutationObserver((mutations) => {
    const emailMessages = document.querySelectorAll(GMAIL_MESSAGE_CONTAINER);

    let subjectText = '';
    const subjectEl = document.querySelector(GMAIL_SUBJECT_CLASS);
    if (subjectEl) {
        subjectText = subjectEl.textContent.toLowerCase();
    }

    emailMessages.forEach(msg => {
        const senderSpan = msg.querySelector(GMAIL_SENDER_ELEMENT);
        if (!senderSpan) return;

        if (msg.dataset.securityProcessed === 'true') return;

        const rawBodyText = msg.textContent || '';
        const combinedText = (rawBodyText + ' ' + subjectText).toLowerCase().replace(/\s+/g, ' ');

        const senderEmail = (senderSpan.getAttribute('email') || senderSpan.innerText).toLowerCase();
        const trueSharerEmail = getTrueSharerEmail(msg);

        let triggeredRule = null;

        for (const rule of SECURITY_RULES) {
            const containsKeyword = rule.keywords.some(k => combinedText.includes(k));

            let brandInContext = true;
            if (rule.contextKeywords && rule.contextKeywords.length > 0) {
                brandInContext = rule.contextKeywords.some(ctx => combinedText.includes(ctx));
            }

            if (containsKeyword && brandInContext) {

                // 1. IS IT EXPLICITLY SAFE?
                let isSafe = false;

                if (rule.safeSenders && rule.safeSenders.some(domain => senderEmail.endsWith(domain))) {
                    isSafe = true;
                }

                if (rule.safeSharerDomains && trueSharerEmail && rule.safeSharerDomains.some(domain => trueSharerEmail.endsWith(domain))) {
                    isSafe = true;
                }

                if (isSafe) {
                    continue;
                }

                // 2. DOES IT REQUIRE A BANNER?
                let triggersBanner = false;

                // If triggerSenders is empty, it defaults to catching ALL non-safe senders
                if (!rule.triggerSenders || rule.triggerSenders.length === 0) {
                    triggersBanner = true;
                } else if (rule.triggerSenders.some(email => senderEmail.includes(email))) {
                    // If it has specific senders (like Drive), it must match one
                    triggersBanner = true;
                }

                // If it is slated to trigger, see if a required body match saves it
                if (triggersBanner && rule.requiresBodyMatch && rule.requiresBodyMatch.length > 0) {
                    const hasBodyMatch = rule.requiresBodyMatch.some(domain => combinedText.includes(domain));
                    if (hasBodyMatch) {
                        triggersBanner = false; // It has the required internal domain, cancel the banner
                    }
                }

                if (triggersBanner) {
                    triggeredRule = rule;
                    break;
                }
            }
        }

        if (triggeredRule) {
            if (!msg.querySelector('.ysd7-security-banner')) {
                const banner = document.createElement('div');
                banner.className = 'ysd7-security-banner';
                banner.style.backgroundColor = '#fff3e0';
                banner.style.color = '#e65100';
                banner.style.padding = '12px 16px';
                banner.style.marginBottom = '15px';
                banner.style.border = '1px solid #ffb74d';
                banner.style.borderLeft = '6px solid #ff9800';
                banner.style.borderRadius = '4px';
                banner.style.fontFamily = 'Google Sans, Roboto, Arial, sans-serif';
                banner.style.fontSize = '14px';

                banner.innerHTML = `
                    <strong style="font-size: 15px;">⚠️ EXTERNAL OR UNVERIFIED ${triggeredRule.brandName.toUpperCase()} LINK</strong><br>
                    This email may contain a <strong>${triggeredRule.brandName}</strong> link. Compromised partner accounts often send malicious links. Before clicking a link, pause and verify the message. If the email is unexpected, asks for information, or directs you to sign in or confirm an account, treat it as suspicious. If you are unsure, <strong>do not interact with the message.</strong>
                `;

                msg.insertBefore(banner, msg.firstChild);
            }
        }

        msg.dataset.securityProcessed = 'true';
    });
});

observer.observe(document.body, { childList: true, subtree: true });
