// src/appstyle.ts
// Business-archetype detection + type-specific rule packs. Different kinds of app have different things
// that matter: a store must defend against card skimmers, an auth portal must not cache the login page,
// a healthcare portal must lock down PII forms. This module fingerprints WHAT KIND of app it is (from
// the homepage — no extra requests) and then runs that archetype's extra rules — but ONLY when the
// archetype is detected confidently, mirroring how framework.ts gates stack checks, so we never
// false-probe an app that isn't that type.
//
// The rule specs are exported so src/catalog.ts lists every one automatically — the top-20 app-type
// tests show up in docs/CHECKS.md with no second copy to keep in sync.
import { safeFetch, sameOrigin } from './core.js';
/**
 * Does this path plausibly address a single article, rather than a homepage,
 * feed, section index or tag listing? Used to decide whether an article-level
 * assertion is even applicable to the page being analysed.
 */
/**
 * Is the analysed MARKUP a single article page (rather than a homepage, feed or
 * listing)? Reads the html itself so an article-level assertion is only made
 * about markup that actually claims to be an article.
 */
export function htmlIsSingleArticle(a) {
    // The strongest declaration a page can make about itself.
    if (/property=["']og:type["']\s+content=["']article["']/i.test(a.hay))
        return true;
    if (/content=["']article["']\s+property=["']og:type["']/i.test(a.hay))
        return true;
    // Otherwise fall back to the URL shape — only meaningful when the markup
    // carries no self-declaration at all.
    return looksLikeArticlePath(a.path);
}
export function looksLikeArticlePath(path) {
    const p = (path || '/').toLowerCase().replace(/\/+$/, '');
    if (!p || p === '/')
        return false;
    const segs = p.split('/').filter(Boolean);
    const last = (segs[segs.length - 1] || '').replace(/\.html?$/, '');
    // Primary signal: a headline-shaped slug. This wins over any prefix, because
    // real sites nest articles under listing-ish roots
    // (e.g. /topics/news/australian-ai-funding-hits-839m.html).
    if (last.split('-').filter(Boolean).length >= 3)
        return true;
    // Secondary: a conventional single-post prefix with a non-numeric slug below
    // it (/blog/hello-world), but not the section root itself (/blog) and not
    // pagination (/blog/2).
    if (segs.length >= 2 && /^(blog|news|articles?|posts?|insights?|stories)$/.test(segs[0])) {
        return !/^\d+$/.test(last);
    }
    return false;
}
function buildAppContext(ctx) {
    const html = ctx.html || '';
    const hay = html.toLowerCase();
    const text = html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').toLowerCase().slice(0, 40_000);
    const jsonLdTypes = [];
    for (const m of html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
        for (const t of m[1].matchAll(/"@type"\s*:\s*"([^"]+)"/g))
            jsonLdTypes.push(t[1].toLowerCase());
    }
    return { html, hay, text, path: (ctx.url.pathname || '/').toLowerCase(), jsonLdTypes, headers: ctx.headers, isHttps: ctx.url.protocol === 'https:' };
}
// A word-boundaried keyword hit in visible text (avoids matching inside class names / attributes).
const kw = (a, ...words) => words.filter((w) => new RegExp(`\\b${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(a.text));
const DETECTORS = [
    { key: 'ecommerce', label: 'E-commerce / online store', signals: [
            { weight: 3, why: 'Product/Offer schema', test: (a) => a.jsonLdTypes.some((t) => /product|offer|aggregateoffer/.test(t)) },
            { weight: 2, why: 'add-to-cart / checkout wording', test: (a) => kw(a, 'add to cart', 'checkout', 'shopping cart').length > 0 || /add[-_ ]to[-_ ]cart/.test(a.hay) },
            { weight: 2, why: 'cart/checkout paths or Shopify/Woo markers', test: (a) => /\/(cart|checkout)\b/.test(a.hay) || /cdn\.shopify|woocommerce|bigcommerce|magento/.test(a.hay) },
            { weight: 1, why: 'price wording', test: (a) => kw(a, 'in stock', 'sold out', 'free shipping').length > 0 },
        ] },
    { key: 'saas-dashboard', label: 'SaaS app / dashboard', signals: [
            { weight: 3, why: 'dashboard/workspace wording', test: (a) => kw(a, 'dashboard', 'workspace').length > 0 },
            { weight: 2, why: 'app shell (mount div + little SSR text)', test: (a) => /<div[^>]+id=["'](root|app|__next)["']/i.test(a.html) && a.text.length < 800 },
            { weight: 1, why: 'sign in / log out wording', test: (a) => kw(a, 'sign in', 'log in', 'log out', 'sign out').length > 0 },
            { weight: 1, why: 'app/dashboard/settings path', test: (a) => /\/(app|dashboard|settings|account)\b/.test(a.path) },
        ] },
    { key: 'marketing-site', label: 'Marketing / landing site', signals: [
            { weight: 2, why: 'CTA wording (get started / book a demo)', test: (a) => kw(a, 'get started', 'book a demo', 'start free', 'request a demo', 'sign up free').length > 0 },
            { weight: 2, why: 'pricing / testimonials', test: (a) => kw(a, 'pricing', 'testimonials', 'trusted by').length > 0 || /\/pricing\b/.test(a.hay) },
            { weight: 1, why: 'features / how it works', test: (a) => kw(a, 'features', 'how it works').length > 0 },
        ] },
    { key: 'blog-cms', label: 'Blog / news / CMS', signals: [
            { weight: 3, why: 'Article/BlogPosting schema', test: (a) => a.jsonLdTypes.some((t) => /article|blogposting|newsarticle/.test(t)) },
            { weight: 2, why: 'RSS/Atom feed link', test: (a) => /type=["']application\/(rss|atom)\+xml["']/i.test(a.html) },
            { weight: 1, why: 'blog/post wording or path', test: (a) => /\/(blog|posts?|news|articles?)\b/.test(a.hay) || kw(a, 'read more', 'posted on', 'by the author').length > 0 },
        ] },
    { key: 'auth-portal', label: 'Auth / login / identity portal', signals: [
            { weight: 3, why: 'password + email input on the page', test: (a) => /<input[^>]+type=["']password["']/i.test(a.html) },
            { weight: 2, why: 'SSO / sign-in wording', test: (a) => kw(a, 'single sign-on', 'sso', 'forgot password', 'reset password').length > 0 || /okta|auth0|workos|keycloak/.test(a.hay) },
            { weight: 1, why: 'login/oauth/saml path', test: (a) => /\/(login|signin|oauth|saml|auth)\b/.test(a.path) },
        ] },
    { key: 'api-backend', label: 'Headless API / JSON service', signals: [
            { weight: 3, why: 'homepage returns JSON, not HTML', test: (a) => /json/.test((a.headers.get('content-type') || '').toLowerCase()) && a.html.length === 0 },
            { weight: 2, why: 'OpenAPI/Swagger/GraphQL wording', test: (a) => /swagger|openapi|graphql|"paths"\s*:/.test(a.hay) },
            { weight: 1, why: 'API wording', test: (a) => kw(a, 'api reference', 'endpoints', 'rate limit').length > 0 },
        ] },
    { key: 'marketplace', label: 'Multi-vendor marketplace', signals: [
            { weight: 2, why: 'sellers/vendors/listings wording', test: (a) => kw(a, 'sellers', 'vendors', 'listings', 'marketplace').length > 0 },
            { weight: 2, why: 'buy & sell + ratings', test: (a) => kw(a, 'buy and sell', 'become a seller', 'reviews', 'ratings').length > 0 },
            { weight: 1, why: 'browse categories', test: (a) => kw(a, 'categories', 'browse').length > 0 },
        ] },
    { key: 'booking', label: 'Booking / scheduling / reservations', signals: [
            { weight: 3, why: 'Reservation/Schedule schema', test: (a) => a.jsonLdTypes.some((t) => /reservation|schedule|event/.test(t)) },
            { weight: 2, why: 'book now / appointment / availability', test: (a) => kw(a, 'book now', 'appointment', 'availability', 'reserve', 'reservation', 'select a time').length > 0 },
            { weight: 1, why: 'booking/calendar path', test: (a) => /\/(book|booking|schedule|appointments?)\b/.test(a.hay) },
        ] },
    { key: 'fintech', label: 'Fintech / banking / payments', signals: [
            { weight: 3, why: 'banking wording (balance/transfer/wallet)', test: (a) => kw(a, 'account balance', 'transfer', 'deposit', 'withdraw', 'wallet', 'transactions').length >= 2 },
            { weight: 2, why: 'payments / KYC / crypto', test: (a) => kw(a, 'kyc', 'aml', 'crypto', 'stablecoin', 'iban', 'routing number', 'debit card').length > 0 },
            { weight: 1, why: 'invest / loan / interest', test: (a) => kw(a, 'invest', 'loan', 'interest rate', 'portfolio').length > 0 },
        ] },
    { key: 'healthcare', label: 'Healthcare / patient portal', signals: [
            { weight: 3, why: 'patient/medical wording', test: (a) => kw(a, 'patient', 'medical record', 'prescription', 'clinic', 'diagnosis').length > 0 },
            { weight: 2, why: 'HIPAA / PHI / appointment with a doctor', test: (a) => kw(a, 'hipaa', 'phi', 'telehealth', 'book an appointment').length > 0 },
            { weight: 1, why: 'health / doctor / provider', test: (a) => kw(a, 'doctor', 'physician', 'healthcare', 'provider').length > 0 },
        ] },
    { key: 'social-community', label: 'Social network / community / forum', signals: [
            { weight: 2, why: 'feed/follow/post wording', test: (a) => kw(a, 'feed', 'follow', 'followers', 'upvote', 'karma').length > 0 },
            { weight: 2, why: 'forum/community + Discourse markers', test: (a) => kw(a, 'community', 'forum', 'discussion', 'reply', 'thread').length > 0 || /discourse/.test(a.hay) },
            { weight: 1, why: 'comment / share', test: (a) => kw(a, 'comments', 'share', 'like').length > 1 },
        ] },
    { key: 'chat-messaging', label: 'Chat / messaging app', signals: [
            { weight: 3, why: 'chat/inbox/conversation wording', test: (a) => kw(a, 'conversation', 'inbox', 'send a message', 'new message', 'typing').length > 0 },
            { weight: 1, why: 'chat/messages path or ws hints', test: (a) => /\/(chat|messages?|inbox)\b/.test(a.hay) || /websocket|socket\.io/.test(a.hay) },
        ] },
    { key: 'file-sharing', label: 'File storage / sharing', signals: [
            { weight: 2, why: 'upload/share/folder wording', test: (a) => kw(a, 'upload', 'shared with you', 'my files', 'folder', 'drive').length > 0 },
            { weight: 2, why: 'file input on the page', test: (a) => /<input[^>]+type=["']file["']/i.test(a.html) },
            { weight: 1, why: 'download link wording', test: (a) => kw(a, 'download', 'shareable link').length > 0 },
        ] },
    { key: 'admin-panel', label: 'Admin / back-office panel', signals: [
            { weight: 3, why: 'admin path or wording', test: (a) => /\/(admin|wp-admin|backoffice|manage)\b/.test(a.path) || kw(a, 'admin panel', 'back office').length > 0 },
            { weight: 1, why: 'manage users / settings', test: (a) => kw(a, 'manage users', 'manage', 'moderation').length > 0 },
        ] },
    { key: 'docs-site', label: 'Documentation / knowledge base', signals: [
            { weight: 2, why: 'docs generator markers', test: (a) => /docusaurus|gitbook|readthedocs|mkdocs|nextra/.test(a.hay) },
            { weight: 2, why: 'docs wording / path', test: (a) => /\/(docs|documentation|reference|guide)s?\b/.test(a.hay) || kw(a, 'getting started', 'api reference', 'documentation').length > 0 },
            { weight: 1, why: 'on this page / edit this page', test: (a) => kw(a, 'on this page', 'edit this page').length > 0 },
        ] },
    { key: 'job-board', label: 'Job board / recruitment', signals: [
            { weight: 3, why: 'JobPosting schema', test: (a) => a.jsonLdTypes.some((t) => /jobposting/.test(t)) },
            { weight: 2, why: 'jobs/careers/apply wording', test: (a) => kw(a, 'apply now', 'job', 'jobs', 'careers', 'vacancy', 'hiring').length > 0 },
            { weight: 1, why: 'jobs/careers path', test: (a) => /\/(jobs?|careers?|vacanc)\b/.test(a.hay) },
        ] },
    { key: 'real-estate', label: 'Real estate / property listings', signals: [
            { weight: 3, why: 'RealEstate/Residence schema', test: (a) => a.jsonLdTypes.some((t) => /realestate|residence|apartment|house/.test(t)) },
            { weight: 2, why: 'property wording', test: (a) => kw(a, 'for sale', 'for rent', 'bedrooms', 'bathrooms', 'square feet', 'listing').length > 0 },
            { weight: 1, why: 'property/listing path', test: (a) => /\/(propert|listing|homes?|rentals?)\b/.test(a.hay) },
        ] },
    { key: 'education-lms', label: 'Education / LMS / courses', signals: [
            { weight: 3, why: 'Course schema', test: (a) => a.jsonLdTypes.some((t) => /course/.test(t)) },
            { weight: 2, why: 'course/lesson/enroll wording', test: (a) => kw(a, 'enroll', 'course', 'lesson', 'curriculum', 'student', 'syllabus').length > 0 || /moodle|canvas lms/.test(a.hay) },
            { weight: 1, why: 'learn / classroom', test: (a) => kw(a, 'learn', 'classroom', 'assignment').length > 0 },
        ] },
    { key: 'crm', label: 'CRM / sales tool', signals: [
            { weight: 3, why: 'CRM wording (leads/pipeline/deals)', test: (a) => kw(a, 'leads', 'pipeline', 'deals', 'opportunities', 'contacts').length >= 2 },
            { weight: 1, why: 'sales / customers', test: (a) => kw(a, 'sales', 'customers', 'accounts').length > 0 },
        ] },
    { key: 'support-helpdesk', label: 'Support / helpdesk / ticketing', signals: [
            { weight: 2, why: 'help center / ticket wording', test: (a) => kw(a, 'help center', 'support ticket', 'submit a ticket', 'knowledge base').length > 0 },
            { weight: 2, why: 'helpdesk vendor markers', test: (a) => /zendesk|intercom|freshdesk|helpscout/.test(a.hay) },
            { weight: 1, why: 'contact support / FAQ', test: (a) => kw(a, 'contact support', 'faq', 'how can we help').length > 0 },
        ] },
];
/** Detect business archetype(s) from the homepage. Returns scored signals, highest first. */
export function detectAppStyles(ctx) {
    const a = buildAppContext(ctx);
    const out = [];
    for (const d of DETECTORS) {
        let score = 0;
        let strong = false;
        const why = [];
        for (const s of d.signals) {
            if (s.test(a)) {
                score += s.weight;
                why.push(s.why);
                if (s.weight >= 3)
                    strong = true;
            }
        }
        if (score > 0)
            out.push({ key: d.key, label: d.label, score, strong, why });
    }
    return out.sort((x, y) => y.score - x.score);
}
const has = (a, name) => !!a.headers.get(name);
const cspPresent = (a) => has(a, 'content-security-policy');
const hstsPresent = (a) => /max-age=\d{4,}/.test(a.headers.get('strict-transport-security') || '');
const frameProtected = (a) => has(a, 'x-frame-options') || /frame-ancestors/i.test(a.headers.get('content-security-policy') || '');
const noStore = (a) => /no-store|private/i.test(a.headers.get('cache-control') || '');
function crossOriginScriptsNoSri(a, base) {
    const tags = [...a.html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
    return tags.filter((t) => {
        const m = t.match(/src\s*=\s*["'](https?:\/\/[^"']+)["']/i);
        return m && !sameOrigin(m[1], base) && !/\bintegrity\s*=/.test(t);
    }).length;
}
const PACKS = [
    { key: 'ecommerce', rules: [
            { id: 'appstyle.ecommerce.csp', title: 'Store has a CSP (card-skimmer defense)', severity: 'high', description: 'A store without a Content-Security-Policy is the prime Magecart target — injected JS can skim card fields.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'Content-Security-Policy present' : 'no enforced CSP on a checkout-bearing site', fix: 'Add a strict Content-Security-Policy — it is the main defense against Magecart card-skimming scripts.' }) },
            { id: 'appstyle.ecommerce.hsts', title: 'Store enforces HSTS on payment traffic', severity: 'high', description: 'Payment pages must never be downgradable to http.',
                run: (_c, a) => ({ pass: a.isHttps && hstsPresent(a), detail: hstsPresent(a) ? 'HSTS present' : 'no HSTS on a payment-handling site', fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains so checkout can never be downgraded to http.' }) },
            { id: 'appstyle.ecommerce.third-party-scripts', title: 'Third-party scripts on the store are pinned (SRI)', severity: 'medium', description: 'Every un-pinned third-party script on a store is a potential skimmer injection point.',
                run: (c, a) => { const n = crossOriginScriptsNoSri(a, c.baseUrl); return n ? { pass: false, detail: `${n} cross-origin <script> without integrity on a store page`, fix: 'Add integrity="sha384-…" + crossorigin to third-party scripts, or self-host them — a hacked vendor CDN can skim cards otherwise.' } : { pass: true, detail: 'no un-pinned cross-origin scripts' }; } },
        ] },
    { key: 'saas-dashboard', rules: [
            { id: 'appstyle.saas.frame-protection', title: 'App is protected from clickjacking', severity: 'medium', description: 'An authenticated app framed by an attacker enables clickjacking of privileged actions.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'X-Frame-Options / frame-ancestors present' : 'no clickjacking protection on an app UI', fix: 'Send X-Frame-Options: DENY (or CSP frame-ancestors \'none\') so the app can\'t be framed for clickjacking.' }) },
            { id: 'appstyle.saas.csp', title: 'App ships a CSP', severity: 'medium', description: 'A dashboard handling user data should constrain script sources.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on an authenticated app', fix: 'Add a Content-Security-Policy to limit XSS blast radius in the app.' }) },
        ] },
    { key: 'marketing-site', rules: [
            { id: 'appstyle.marketing.open-graph', title: 'Landing page has Open Graph tags', severity: 'low', description: 'Marketing links that don\'t unfurl with a title/image lose clicks when shared.',
                run: (_c, a) => { const og = /property=["']og:(title|image)["']/i.test(a.html); return { pass: og, detail: og ? 'og:title/og:image present' : 'no Open Graph tags on a marketing page', fix: 'Add og:title, og:description and og:image so shared links unfurl with a preview.' }; } },
            { id: 'appstyle.marketing.compression', title: 'Landing page is compressed', severity: 'low', description: 'Conversion drops with load time; an uncompressed landing page is an easy win.',
                run: (_c, a) => { const enc = a.headers.get('content-encoding') || ''; return { pass: !!enc, detail: enc ? `content-encoding: ${enc}` : 'landing page served uncompressed', fix: 'Enable gzip/brotli — it shrinks the page ~70% and directly helps conversion.' }; } },
        ] },
    { key: 'blog-cms', rules: [
            { id: 'appstyle.blog.feed', title: 'Blog exposes an RSS/Atom feed', severity: 'low', description: 'A content site without a feed loses syndication and reader tooling.',
                run: (_c, a) => { const feed = /type=["']application\/(rss|atom)\+xml["']/i.test(a.html); return { pass: feed, detail: feed ? 'feed <link> present' : 'no RSS/Atom feed advertised', fix: 'Add <link rel="alternate" type="application/rss+xml"> so readers and aggregators can subscribe.' }; } },
            { id: 'appstyle.blog.article-schema', title: 'Articles carry JSON-LD schema', severity: 'low', description: 'Article structured data drives rich results in search.',
                // App-style rules analyse the HOMEPAGE (see appstyle.detected). A homepage
                // is not an article, so it legitimately carries WebSite/Organization
                // schema and no Article schema — asserting here failed on every correctly
                // built news site, including ones whose article pages DO emit full
                // NewsArticle JSON-LD. A check that cries wolf gets ignored, so only
                // judge when the analysed page actually looks like an article.
                run: (_c, a) => {
                    const ok = a.jsonLdTypes.some((t) => /article|blogposting|newsarticle/.test(t));
                    if (ok)
                        return { pass: true, detail: 'Article JSON-LD present' };
                    // Gate on the ANALYSED HTML, not the requested path: app-style rules run
                    // against the homepage, so `a.path` can name an article while `a.html`
                    // is the home page. Judging an article-level rule from homepage markup
                    // is what produced the false positive.
                    if (!htmlIsSingleArticle(a)) {
                        return { pass: true, detail: 'not evaluated: the analysed page is not a single article (app-style rules read the homepage) — check an article page directly for its Article/NewsArticle schema' };
                    }
                    return { pass: false, detail: 'no Article/BlogPosting structured data', fix: 'Add Article JSON-LD (headline, author, datePublished) for rich search results.' };
                } },
        ] },
    { key: 'auth-portal', rules: [
            { id: 'appstyle.auth.https', title: 'Login is served over HTTPS', severity: 'high', description: 'Credentials entered on an http page are sent in clear text.',
                run: (_c, a) => ({ pass: a.isHttps, detail: a.isHttps ? 'login served over https' : 'login page is not https', fix: 'Serve the login page (and its form action) over https only.' }) },
            { id: 'appstyle.auth.no-cache', title: 'Login page is not cached', severity: 'medium', description: 'A cached login/identity page can leak on shared machines and proxies.',
                run: (_c, a) => ({ pass: noStore(a), detail: noStore(a) ? 'Cache-Control no-store/private' : 'login page lacks anti-caching headers', fix: 'Send Cache-Control: no-store on auth pages so credentials/forms aren\'t retained by browsers or shared proxies.' }) },
            { id: 'appstyle.auth.form-secure', title: 'Login form posts to an https target', severity: 'high', description: 'A login <form> whose action is http (or method GET) leaks credentials.',
                run: (_c, a) => {
                    const form = a.html.match(/<form\b[^>]*>/i)?.[0] || '';
                    if (!/<input[^>]+type=["']password["']/i.test(a.html))
                        return null;
                    const action = form.match(/action\s*=\s*["']([^"']+)["']/i)?.[1] || '';
                    const method = (form.match(/method\s*=\s*["']([^"']+)["']/i)?.[1] || 'get').toLowerCase();
                    const bad = /^http:\/\//i.test(action) || method === 'get';
                    return { pass: !bad, detail: bad ? `login form method=${method} action=${action || '(self)'}` : 'login form posts securely', fix: 'Use method="post" and an https action for the login form so credentials aren\'t exposed in the URL or over http.' };
                } },
        ] },
    { key: 'api-backend', rules: [
            { id: 'appstyle.api.docs-public', title: 'API docs/spec are not wide open', severity: 'medium', description: 'A public OpenAPI/Swagger spec hands attackers your full endpoint map.',
                run: async (c, _a) => {
                    for (const p of ['/openapi.json', '/swagger.json', '/api-docs']) {
                        const res = await safeFetch(c.origin + p, { redirect: 'follow' }, c.opts.timeoutMs);
                        if (res && res.ok) {
                            const b = (await res.text().catch(() => '')).slice(0, 2000);
                            if (/"(?:openapi|swagger)"\s*:|swagger-ui/i.test(b))
                                return { pass: false, detail: `${p} serves an API spec publicly`, fix: 'Gate the OpenAPI/Swagger spec behind auth (or don\'t ship it to production) so your endpoint map isn\'t public.' };
                        }
                    }
                    return { pass: true, detail: 'no public OpenAPI/Swagger spec found' };
                } },
            { id: 'appstyle.api.json-errors', title: 'API returns JSON errors, not HTML stack traces', severity: 'medium', description: 'An API that returns an HTML error page for a bad path is likely leaking a framework debug page.',
                run: async (c, _a) => {
                    const res = await safeFetch(c.origin + '/__vta_api_probe__', { redirect: 'follow', headers: { accept: 'application/json' } }, c.opts.timeoutMs);
                    if (!res)
                        return null;
                    const ct = (res.headers.get('content-type') || '').toLowerCase();
                    const htmlErr = ct.includes('html');
                    return { pass: !htmlErr, detail: htmlErr ? 'unknown API path returned an HTML error page' : `unknown path returned ${res.status} ${ct || '(no type)'}`, fix: 'Return structured JSON errors (with a generic message) from the API — never an HTML/framework debug page.' };
                } },
        ] },
    { key: 'marketplace', rules: [
            { id: 'appstyle.marketplace.frame-protection', title: 'Marketplace is protected from clickjacking', severity: 'medium', description: 'Purchase/checkout actions on a marketplace must not be framable.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no clickjacking protection', fix: 'Send X-Frame-Options: DENY or a CSP frame-ancestors directive.' }) },
            { id: 'appstyle.marketplace.csp', title: 'Marketplace ships a CSP', severity: 'medium', description: 'User-generated listings raise XSS risk; a CSP limits the blast radius.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a UGC-heavy marketplace', fix: 'Add a Content-Security-Policy — listings are user-generated content and a stored-XSS risk.' }) },
        ] },
    { key: 'booking', rules: [
            { id: 'appstyle.booking.https', title: 'Booking flow is served over HTTPS', severity: 'high', description: 'Booking captures names, contact details and often payment — it must be https.',
                run: (_c, a) => ({ pass: a.isHttps, detail: a.isHttps ? 'served over https' : 'booking flow not https', fix: 'Serve the booking flow over https only — it collects personal and payment data.' }) },
            { id: 'appstyle.booking.csp', title: 'Booking app ships a CSP', severity: 'medium', description: 'Payment + PII collection warrants a CSP.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a booking/payment flow', fix: 'Add a Content-Security-Policy to protect the payment/PII capture step.' }) },
        ] },
    { key: 'fintech', rules: [
            { id: 'appstyle.fintech.hsts', title: 'Fintech enforces HSTS', severity: 'high', description: 'Financial apps must never be downgradable to http.',
                run: (_c, a) => ({ pass: a.isHttps && hstsPresent(a), detail: hstsPresent(a) ? 'HSTS present' : 'no HSTS on a financial app', fix: 'Send Strict-Transport-Security with a long max-age + includeSubDomains (ideally preload).' }) },
            { id: 'appstyle.fintech.csp', title: 'Fintech ships a strict CSP', severity: 'high', description: 'Money-movement UIs are high-value XSS targets.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a financial app', fix: 'Add a strict Content-Security-Policy — a financial UI is a prime XSS/skimming target.' }) },
            { id: 'appstyle.fintech.no-cache', title: 'Fintech responses are non-cacheable', severity: 'medium', description: 'Account/balance data must not be cached by shared proxies or browsers.',
                run: (_c, a) => ({ pass: noStore(a), detail: noStore(a) ? 'Cache-Control no-store/private' : 'no anti-caching headers on a financial app', fix: 'Send Cache-Control: no-store on financial pages so balances/statements aren\'t cached.' }) },
        ] },
    { key: 'healthcare', rules: [
            { id: 'appstyle.healthcare.https', title: 'Health portal is HTTPS-only', severity: 'high', description: 'PHI must only ever travel over TLS.',
                run: (_c, a) => ({ pass: a.isHttps && hstsPresent(a), detail: hstsPresent(a) ? 'HTTPS + HSTS' : 'no HSTS on a health portal', fix: 'Enforce HTTPS with HSTS — protected health information must never be sent over http.' }) },
            { id: 'appstyle.healthcare.no-cache', title: 'Health portal is non-cacheable', severity: 'medium', description: 'PHI must not linger in browser or proxy caches.',
                run: (_c, a) => ({ pass: noStore(a), detail: noStore(a) ? 'Cache-Control no-store/private' : 'no anti-caching on a health portal', fix: 'Send Cache-Control: no-store so patient data isn\'t cached on shared machines.' }) },
        ] },
    { key: 'social-community', rules: [
            { id: 'appstyle.social.csp', title: 'Community app ships a CSP', severity: 'medium', description: 'User posts/comments make stored XSS the top risk for social apps.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a UGC community app', fix: 'Add a Content-Security-Policy — user-generated posts are the main stored-XSS vector.' }) },
            { id: 'appstyle.social.frame-protection', title: 'Community app resists clickjacking', severity: 'medium', description: 'Framing enables like/follow/post clickjacking.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no clickjacking protection', fix: 'Send X-Frame-Options: DENY or CSP frame-ancestors to stop action clickjacking.' }) },
        ] },
    { key: 'chat-messaging', rules: [
            { id: 'appstyle.chat.csp', title: 'Chat app ships a CSP', severity: 'medium', description: 'Messages are attacker-controlled content rendered to other users — stored XSS risk.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a messaging app', fix: 'Add a Content-Security-Policy — message bodies are untrusted content.' }) },
            { id: 'appstyle.chat.frame-protection', title: 'Chat app resists clickjacking', severity: 'low', description: 'A framed chat UI can be tricked into sending/approving.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no framing protection', fix: 'Send X-Frame-Options: DENY or CSP frame-ancestors.' }) },
        ] },
    { key: 'file-sharing', rules: [
            { id: 'appstyle.files.nosniff', title: 'File app sends X-Content-Type-Options: nosniff', severity: 'medium', description: 'Without nosniff, an uploaded file can be sniffed and executed as HTML/script.',
                run: (_c, a) => { const ok = /nosniff/i.test(a.headers.get('x-content-type-options') || ''); return { pass: ok, detail: ok ? 'nosniff present' : 'no X-Content-Type-Options on a file-serving app', fix: 'Send X-Content-Type-Options: nosniff so uploaded files can\'t be MIME-sniffed into executable HTML.' }; } },
            { id: 'appstyle.files.csp', title: 'File app ships a CSP', severity: 'medium', description: 'A CSP (esp. sandbox / object-src) limits what an uploaded/served file can do.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a file-sharing app', fix: 'Add a CSP (and serve user files from a separate origin) so an uploaded file can\'t run in your app\'s context.' }) },
        ] },
    { key: 'admin-panel', rules: [
            { id: 'appstyle.admin.noindex', title: 'Admin panel is not search-indexable', severity: 'low', description: 'An admin panel showing up in search advertises the attack surface.',
                run: async (c, a) => {
                    const metaNoindex = /<meta[^>]+name=["']robots["'][^>]+noindex/i.test(a.html) || /noindex/i.test(a.headers.get('x-robots-tag') || '');
                    if (metaNoindex)
                        return { pass: true, detail: 'admin marked noindex' };
                    const robots = await safeFetch(c.origin + '/robots.txt', { redirect: 'follow' }, c.opts.timeoutMs);
                    const disallowed = robots && robots.ok ? /disallow:\s*\/(admin|wp-admin|manage)/i.test(await robots.text().catch(() => '')) : false;
                    return { pass: !!disallowed, detail: disallowed ? 'admin path disallowed in robots.txt' : 'admin panel is not marked noindex / disallowed', fix: 'Add a robots noindex (or Disallow the admin path) so the back-office isn\'t indexed — and keep it behind auth regardless.' };
                } },
            { id: 'appstyle.admin.frame-protection', title: 'Admin panel resists clickjacking', severity: 'medium', description: 'Admin actions are the highest-value clickjacking target.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no clickjacking protection on an admin UI', fix: 'Send X-Frame-Options: DENY or CSP frame-ancestors \'none\' on admin pages.' }) },
        ] },
    { key: 'docs-site', rules: [
            { id: 'appstyle.docs.canonical', title: 'Docs pages set a canonical URL', severity: 'low', description: 'Versioned/duplicated docs need canonicals to avoid SEO cannibalization.',
                run: (_c, a) => { const ok = /<link[^>]+rel=["']canonical["']/i.test(a.html); return { pass: ok, detail: ok ? 'canonical present' : 'no canonical on a docs page', fix: 'Add <link rel="canonical"> so duplicated/versioned docs pages don\'t split ranking.' }; } },
            { id: 'appstyle.docs.search', title: 'Docs site has search', severity: 'low', description: 'Docs without search are hard to use at any size.',
                run: (_c, a) => { const ok = /<input[^>]+type=["']search["']/i.test(a.html) || /algolia|docsearch|search/i.test(a.hay); return { pass: ok, detail: ok ? 'search present' : 'no search UI detected on a docs site', fix: 'Add search (e.g. Algolia DocSearch) — it\'s the primary way people navigate docs.' }; } },
        ] },
    { key: 'job-board', rules: [
            { id: 'appstyle.jobs.schema', title: 'Job posts carry JobPosting schema', severity: 'low', description: 'JobPosting structured data is required for Google Jobs inclusion.',
                run: (_c, a) => { const ok = a.jsonLdTypes.some((t) => /jobposting/.test(t)); return { pass: ok, detail: ok ? 'JobPosting JSON-LD present' : 'no JobPosting structured data', fix: 'Add JobPosting JSON-LD (title, hiringOrganization, datePosted, location) so listings appear in Google Jobs.' }; } },
            { id: 'appstyle.jobs.apply-https', title: 'Job board is served over HTTPS', severity: 'medium', description: 'Applications carry résumés and personal data.',
                run: (_c, a) => ({ pass: a.isHttps, detail: a.isHttps ? 'served over https' : 'job board not https', fix: 'Serve the job board over https — applications include personal data and CVs.' }) },
        ] },
    { key: 'real-estate', rules: [
            { id: 'appstyle.realestate.schema', title: 'Listings carry structured data', severity: 'low', description: 'Property structured data drives rich real-estate search results.',
                run: (_c, a) => { const ok = a.jsonLdTypes.some((t) => /realestate|residence|apartment|house|product|offer/.test(t)); return { pass: ok, detail: ok ? 'listing structured data present' : 'no property/offer structured data', fix: 'Add RealEstateListing/Product JSON-LD (price, address, features) for rich listing results.' }; } },
            { id: 'appstyle.realestate.og', title: 'Listings unfurl when shared', severity: 'low', description: 'Property links are shared constantly — they should preview.',
                run: (_c, a) => { const og = /property=["']og:(title|image)["']/i.test(a.html); return { pass: og, detail: og ? 'Open Graph present' : 'no Open Graph on a listing page', fix: 'Add og:title/og:image so shared property links show a photo + title.' }; } },
        ] },
    { key: 'education-lms', rules: [
            { id: 'appstyle.lms.csp', title: 'LMS ships a CSP', severity: 'medium', description: 'LMS platforms host user/instructor content and often minors\' data.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on an LMS', fix: 'Add a Content-Security-Policy — course/assignment content is user-generated.' }) },
            { id: 'appstyle.lms.https', title: 'LMS is served over HTTPS', severity: 'medium', description: 'Student records and (often) minors\' data require TLS.',
                run: (_c, a) => ({ pass: a.isHttps, detail: a.isHttps ? 'served over https' : 'LMS not https', fix: 'Serve the LMS over https — it holds student records.' }) },
        ] },
    { key: 'crm', rules: [
            { id: 'appstyle.crm.frame-protection', title: 'CRM resists clickjacking', severity: 'medium', description: 'A framed CRM enables clickjacking of record edits/exports.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no clickjacking protection on a CRM', fix: 'Send X-Frame-Options: DENY or CSP frame-ancestors.' }) },
            { id: 'appstyle.crm.no-cache', title: 'CRM responses are non-cacheable', severity: 'medium', description: 'Customer records must not be cached by shared proxies.',
                run: (_c, a) => ({ pass: noStore(a), detail: noStore(a) ? 'Cache-Control no-store/private' : 'no anti-caching on a CRM', fix: 'Send Cache-Control: no-store so customer PII isn\'t cached.' }) },
        ] },
    { key: 'support-helpdesk', rules: [
            { id: 'appstyle.support.csp', title: 'Helpdesk ships a CSP', severity: 'medium', description: 'Ticket bodies are attacker-controlled content shown to agents — stored XSS risk.',
                run: (_c, a) => ({ pass: cspPresent(a), detail: cspPresent(a) ? 'CSP present' : 'no CSP on a helpdesk', fix: 'Add a Content-Security-Policy — ticket content is untrusted and rendered to agents.' }) },
            { id: 'appstyle.support.frame-protection', title: 'Helpdesk resists clickjacking', severity: 'low', description: 'A framed agent console can be clickjacked into actions.',
                run: (_c, a) => ({ pass: frameProtected(a), detail: frameProtected(a) ? 'framing protection present' : 'no framing protection', fix: 'Send X-Frame-Options: DENY or CSP frame-ancestors.' }) },
        ] },
];
const LABELS = Object.fromEntries(DETECTORS.map((d) => [d.key, d.label]));
const f = (id, title, severity, pass, detail, fix) => ({ category: 'appstyle', id, title, severity, pass, detail, fix });
/** Confidence needed before we run an archetype's rules (avoids false-probing a misdetected type). */
const CONFIDENCE_THRESHOLD = 3;
/**
 * appstyle category: detect the business archetype, then run that type's rule pack. Only archetypes at
 * or above the confidence threshold run (top 2 max), so a marketing site isn't scanned as a bank.
 */
export async function appStyleChecks(ctx) {
    if (!ctx.res)
        return [];
    const a = buildAppContext(ctx);
    const styles = detectAppStyles(ctx);
    // Run a type's rules only when we're confident it IS that type: the single best match, plus any other
    // that cleared the bar via a STRONG (distinctive, weight-3) signal — not a lone nav-link/keyword. This
    // stops a store's "Careers" link from getting job-board page rules run against its homepage.
    const atThreshold = styles.filter((s) => s.score >= CONFIDENCE_THRESHOLD);
    const confident = atThreshold.filter((s, i) => i === 0 || s.strong).slice(0, 2);
    if (!confident.length) {
        return [f('appstyle.none', 'App type not confidently identified', 'info', true, styles.length ? `low-confidence guesses: ${styles.slice(0, 3).map((s) => `${s.key} (${s.score})`).join(', ')}` : 'no distinctive app-type markers on the homepage')];
    }
    const out = [f('appstyle.detected', `App type: ${confident.map((s) => s.label).join(', ')}`, 'info', true, confident.map((s) => `${s.key} [score ${s.score}: ${s.why.join('; ')}]`).join(' | '))];
    for (const s of confident) {
        const pack = PACKS.find((p) => p.key === s.key);
        if (!pack)
            continue;
        for (const rule of pack.rules) {
            let res = null;
            try {
                res = await rule.run(ctx, a);
            }
            catch {
                res = null;
            }
            if (!res)
                continue;
            out.push(f(rule.id, rule.title, rule.severity, res.pass, res.detail, res.pass ? undefined : res.fix));
        }
    }
    return out;
}
export function appStyleRuleSpecs() {
    const specs = [];
    for (const pack of PACKS) {
        for (const rule of pack.rules) {
            specs.push({ id: rule.id, key: pack.key, label: LABELS[pack.key], title: rule.title, severity: rule.severity, description: rule.description });
        }
    }
    return specs;
}
export const APP_STYLE_KEYS = DETECTORS.map((d) => d.key);
