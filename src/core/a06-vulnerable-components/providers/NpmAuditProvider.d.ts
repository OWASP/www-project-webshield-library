export type NpmAuditExec = (command: string, args: string[], options: {
    cwd?: string;
    shell?: boolean;
    maxBuffer?: number;
}) => Promise<{
    stdout: string;
}>;
export class NpmAuditProvider {
    /**
     * @param options `cwd` is the project to audit (defaults to the current working directory);
     *   `exec` is injectable for tests, and defaults to a promisified
     *   `child_process.execFile`.
     */
    constructor(options?: {
        cwd?: string;
        exec?: NpmAuditExec;
    });
    cwd: string | undefined;
    exec: NpmAuditExec | undefined;
    scan(): Promise<{
        name: string;
        severity: string;
        currentVersion: string | null;
        fixedVersion: string | null;
    }[]>;
}
