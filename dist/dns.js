// src/dns.ts
// Email + DNS hygiene, black-box from the hostname: SPF & DMARC (anti-spoofing), CAA (who may issue
// certs), and a dangling-CNAME → subdomain-takeover heuristic. The record-gathering is split from the
// grading so the grader (evaluateDnsHygiene) is a pure, fully-testable function.
import { promises as dns } from 'node:dns';
const f = (id, title, severity, pass, detail, fix) => ({ category: 'dns', id, title, severity, pass, detail, fix });
/** Best-effort registrable apex: last two labels. Good for `sub.example.com`; imperfect for multi-part
 *  public suffixes (`example.co.uk`) — acceptable for a zero-dep black-box check. */
export function apexOf(hostname) {
    const parts = hostname.split('.').filter(Boolean);
    return parts.length <= 2 ? hostname : parts.slice(-2).join('.');
}
/** Pure grader — deterministic given the gathered records, so it unit-tests without touching the network. */
export function evaluateDnsHygiene(r) {
    const out = [];
    // SPF (apex TXT with v=spf1).
    const spf = r.apexTxt.find((t) => /^v=spf1\b/i.test(t.trim()));
    out.push(f('dns.spf', spf ? 'SPF record present' : 'No SPF record', spf ? 'info' : 'medium', !!spf, spf ? `${r.apex}: ${spf.slice(0, 120)}` : `no v=spf1 TXT on ${r.apex}`, spf ? undefined : `Publish an SPF TXT on ${r.apex} (e.g. "v=spf1 include:_spf.google.com -all") so others can't spoof mail from your domain.`));
    // DMARC (_dmarc TXT with v=DMARC1) + policy strength.
    const dmarc = r.dmarcTxt.find((t) => /v=DMARC1\b/i.test(t));
    if (!dmarc) {
        out.push(f('dns.dmarc', 'No DMARC record', 'medium', false, `no v=DMARC1 TXT on _dmarc.${r.apex}`, `Publish _dmarc.${r.apex} TXT "v=DMARC1; p=reject; rua=mailto:you@${r.apex}" to stop spoofing and get reports.`));
    }
    else {
        const policy = (dmarc.match(/\bp\s*=\s*(none|quarantine|reject)/i)?.[1] || 'none').toLowerCase();
        const weak = policy === 'none';
        out.push(f('dns.dmarc', `DMARC policy p=${policy}`, weak ? 'low' : 'info', !weak, `_dmarc.${r.apex}: ${dmarc.slice(0, 120)}`, weak ? 'p=none only monitors — move to p=quarantine then p=reject once your legitimate senders pass.' : undefined));
    }
    // CAA (which CAs may issue certs for the domain).
    out.push(f('dns.caa', r.hasCaa ? 'CAA record present' : 'No CAA record', 'low', r.hasCaa, r.hasCaa ? `${r.apex} restricts cert issuance via CAA` : `no CAA record on ${r.apex}`, r.hasCaa ? undefined : `Add a CAA record on ${r.apex} (e.g. 0 issue "letsencrypt.org") so only your CA can issue certs.`));
    // Dangling CNAME → subdomain takeover.
    if (r.danglingCnameTarget) {
        out.push(f('dns.dangling-cname', 'Dangling CNAME (subdomain takeover risk)', 'high', false, `${r.hostname} is a CNAME to ${r.danglingCnameTarget}, which does not resolve — an attacker who claims that target can serve content on your subdomain`, 'Remove the CNAME, or re-claim the target resource. Never leave a CNAME pointing at a de-provisioned host.'));
    }
    return out;
}
/** Gather the DNS records for a host (all lookups fail soft to empty/false). */
export async function gatherDns(hostname) {
    const apex = apexOf(hostname);
    const txt = async (name) => {
        try {
            return (await dns.resolveTxt(name)).map((chunks) => chunks.join(''));
        }
        catch {
            return [];
        }
    };
    const [apexTxt, dmarcTxt, hasCaa, danglingCnameTarget] = await Promise.all([
        txt(apex),
        txt(`_dmarc.${apex}`),
        dns.resolveCaa(apex).then((r) => r.length > 0).catch(() => false),
        (async () => {
            try {
                const cnames = await dns.resolveCname(hostname); // throws ENODATA when there's no CNAME
                for (const target of cnames) {
                    try {
                        await dns.lookup(target);
                    }
                    catch {
                        return target;
                    } // target doesn't resolve → dangling
                }
            }
            catch { /* no CNAME (typical for an apex or A-record host) — not dangling */ }
            return null;
        })(),
    ]);
    return { hostname, apex, apexTxt, dmarcTxt, hasCaa, danglingCnameTarget };
}
export async function dnsChecks(ctx) {
    const records = await gatherDns(ctx.url.hostname);
    return evaluateDnsHygiene(records);
}
