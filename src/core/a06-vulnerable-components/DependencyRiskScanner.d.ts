export class DependencyRiskScanner {
    /**
     * @param {{scan: () => Promise<Array<{name:string,severity:string,fixedVersion?:string,currentVersion?:string}>>}} provider
     */
    constructor(provider: {
        scan: () => Promise<Array<{
            name: string;
            severity: string;
            fixedVersion?: string;
            currentVersion?: string;
        }>>;
    });
    provider: {
        scan: () => Promise<Array<{
            name: string;
            severity: string;
            fixedVersion?: string;
            currentVersion?: string;
        }>>;
    };
    scan(): Promise<{
        package: string;
        severity: string;
        fixedVersion: string;
        currentVersion: string;
    }[]>;
    passesPolicy(threshold?: string): Promise<{
        pass: boolean;
        blocked: {
            package: string;
            severity: string;
            fixedVersion: string;
            currentVersion: string;
        }[];
        results: {
            package: string;
            severity: string;
            fixedVersion: string;
            currentVersion: string;
        }[];
    }>;
}
