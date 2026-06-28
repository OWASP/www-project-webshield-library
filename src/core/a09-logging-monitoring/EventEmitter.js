export class EventEmitter {
  constructor() {
    this.listeners = new Map();
  }

  on(eventName, listener) {
    const existing = this.listeners.get(eventName) || new Set();
    existing.add(listener);
    this.listeners.set(eventName, existing);
    return () => this.off(eventName, listener);
  }

  off(eventName, listener) {
    const existing = this.listeners.get(eventName);
    if (!existing) return;
    existing.delete(listener);
    if (existing.size === 0) this.listeners.delete(eventName);
  }

  emit(eventName, payload) {
    const existing = this.listeners.get(eventName);
    if (!existing) return;
    for (const listener of existing) {
      listener(payload);
    }
  }
}