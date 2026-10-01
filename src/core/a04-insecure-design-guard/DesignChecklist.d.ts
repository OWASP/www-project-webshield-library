export class DesignChecklist {
    constructor(requiredControls?: any[]);
    requiredControls: any[];
    validate(controlSet: any): {
        valid: boolean;
        missing: any[];
    };
}
