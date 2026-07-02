export type StackName = 'Next.js' | 'Nuxt' | 'WordPress' | 'Laravel' | 'Django' | 'Rails' | 'Spring Boot' | 'ASP.NET' | 'Express' | 'PHP';
export interface StackSignal {
    name: StackName;
    confidence: 'high' | 'medium' | 'low';
    why: string[];
}
export interface DetectInput {
    html: string;
    headers: Headers;
    setCookie: string[];
}
/** Fingerprint the stack(s). Confidence: high = a weight-2 signal or ≥2 signals; medium = one weight-1; else low. */
export declare function detectStacks(inp: DetectInput): StackSignal[];
