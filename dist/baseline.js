// src/baseline.ts
// Baseline / diff mode: record today's failing findings to a committed file, then on later runs only
// fail CI on findings that AREN'T in the baseline. This is what makes the scanner adoptable on a
// legacy app — you snapshot the current debt once and gate on regressions from then on.
/** Stable identity for a finding across runs. `id` already encodes the check + any per-item suffix
 *  (e.g. `cookie.sid`, `exposed/.env`), so it's the right grain to accept/ignore individually. */
export function findingKey(f) {
    return f.id;
}
/** Build a baseline from a scan's failing findings. */
export function buildBaseline(findings, createdFor) {
    const keys = [...new Set(findings.filter((f) => !f.pass).map(findingKey))].sort();
    return createdFor ? { keys, createdFor } : { keys };
}
/** Partition failing findings into new vs. already-baselined. Passing findings are ignored. */
export function applyBaseline(findings, baseline) {
    const accepted = new Set(baseline.keys);
    const newFailures = [];
    const baselined = [];
    for (const f of findings) {
        if (f.pass)
            continue;
        (accepted.has(findingKey(f)) ? baselined : newFailures).push(f);
    }
    return { newFailures, baselined };
}
