export class EventEmitter {
    listeners: Map<any, any>;
    on(eventName: any, listener: any): () => void;
    off(eventName: any, listener: any): void;
    emit(eventName: any, payload: any): void;
}
