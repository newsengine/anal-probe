/** Default Chrome profiles dir per-OS. */
export declare function defaultProfilesDir(): string;
/** Build a minimal throwaway user-data-dir seeded with just one source profile's cookies. */
export declare function seedProfile(profilesDir: string, srcProfile: string, tag: string): string;
export interface Session {
    browser: any;
    close: () => Promise<void>;
}
/** Launch isolated Chrome for a profile and connect Playwright over CDP. Caller must close(). */
export declare function launchProfile(opts: {
    profilesDir: string;
    srcProfile: string;
    tag: string;
    port: number;
}): Promise<Session>;
