import type { Finding } from './types.js';
export interface InitOptions {
    cwd: string;
    url: string;
    projectName?: string;
    findings?: Finding[];
    /** Write GitHub Actions workflow. Default true. */
    ci?: boolean;
}
export interface InitResult {
    written: string[];
    skipped: string[];
}
export declare function initRepo(opts: InitOptions & {
    force?: boolean;
}): InitResult;
