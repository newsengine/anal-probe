import { resolveTxt } from 'node:dns/promises';

/** Expect TXT: vibetesting-verify=<token> (or legacy shipcheck-verify=) on host or _vta.<host>. */
export async function verifyDomainOwnership(hostname: string, token: string): Promise<{
  ok: boolean;
  detail: string;
}> {
  const expected = [`vibetesting-verify=${token}`, `shipcheck-verify=${token}`];
  const names = [hostname, `_vta.${hostname}`, `_shipcheck.${hostname}`];

  for (const name of names) {
    try {
      const records = await resolveTxt(name);
      const flat = records.map((r) => r.join(''));
      if (flat.some((t) => expected.some((e) => t.includes(e)))) {
        return { ok: true, detail: `Found verification TXT on ${name}` };
      }
    } catch {
      /* NXDOMAIN etc */
    }
  }

  // Dev escape hatch for localhost / demo
  if (
    process.env.VTA_SKIP_DNS_VERIFY === '1' ||
    process.env.SHIPCHECK_SKIP_DNS_VERIFY === '1' || // legacy alias
    hostname === 'localhost' ||
    hostname.endsWith('.local')
  ) {
    return { ok: true, detail: 'Dev skip DNS verify' };
  }

  return {
    ok: false,
    detail: `Add a DNS TXT record on ${hostname} or _vta.${hostname} with value: vibetesting-verify=${token}`,
  };
}

export function hostnameFromUrl(url: string): string {
  return new URL(url).hostname.toLowerCase();
}
