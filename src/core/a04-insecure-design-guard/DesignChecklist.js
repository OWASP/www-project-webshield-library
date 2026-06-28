export class DesignChecklist {
  constructor(requiredControls = []) {
    this.requiredControls = requiredControls;
  }

  validate(controlSet) {
    const present = new Set(controlSet || []);
    const missing = this.requiredControls.filter((control) => !present.has(control));
    return {
      valid: missing.length === 0,
      missing
    };
  }
}