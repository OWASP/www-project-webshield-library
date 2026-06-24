/**
 * EventEmitter Tests
 */

import { EventEmitter } from '../EventEmitter';

describe('EventEmitter', () => {
  let emitter: EventEmitter;

  beforeEach(() => {
    emitter = new EventEmitter();
  });

  describe('Event Registration', () => {
    it('should register event listener', () => {
      const listener = jest.fn();
      emitter.on('test-event', listener);

      expect(emitter.listenerCount('test-event')).toBe(1);
    });

    it('should handle multiple listeners for same event', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      emitter.on('test-event', listener1);
      emitter.on('test-event', listener2);

      expect(emitter.listenerCount('test-event')).toBe(2);
    });
  });

  describe('Event Emission', () => {
    it('should call listener on event emit', () => {
      const listener = jest.fn();
      emitter.on('test-event', listener);

      emitter.emit('test-event', 'data');

      expect(listener).toHaveBeenCalledWith('data');
    });

    it('should pass multiple arguments to listener', () => {
      const listener = jest.fn();
      emitter.on('test-event', listener);

      emitter.emit('test-event', 'arg1', 'arg2', 'arg3');

      expect(listener).toHaveBeenCalledWith('arg1', 'arg2', 'arg3');
    });

    it('should return true if event was emitted', () => {
      const listener = jest.fn();
      emitter.on('test-event', listener);

      const result = emitter.emit('test-event', 'data');

      expect(result).toBe(true);
    });

    it('should return false if no listeners', () => {
      const result = emitter.emit('non-existent', 'data');

      expect(result).toBe(false);
    });

    it('should call all listeners', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      emitter.on('test-event', listener1);
      emitter.on('test-event', listener2);

      emitter.emit('test-event', 'data');

      expect(listener1).toHaveBeenCalledWith('data');
      expect(listener2).toHaveBeenCalledWith('data');
    });
  });

  describe('Once', () => {
    it('should register one-time listener', () => {
      const listener = jest.fn();
      emitter.once('test-event', listener);

      emitter.emit('test-event', 'data1');
      emitter.emit('test-event', 'data2');

      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenCalledWith('data1');
    });
  });

  describe('Listener Removal', () => {
    it('should remove listener', () => {
      const listener = jest.fn();
      emitter.on('test-event', listener);

      emitter.off('test-event', listener);

      emitter.emit('test-event', 'data');

      expect(listener).not.toHaveBeenCalled();
    });

    it('should not affect other listeners', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      emitter.on('test-event', listener1);
      emitter.on('test-event', listener2);

      emitter.off('test-event', listener1);

      emitter.emit('test-event', 'data');

      expect(listener1).not.toHaveBeenCalled();
      expect(listener2).toHaveBeenCalledWith('data');
    });

    it('should remove all listeners for event', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      emitter.on('test-event', listener1);
      emitter.on('test-event', listener2);

      emitter.removeAllListeners('test-event');

      expect(emitter.listenerCount('test-event')).toBe(0);
    });

    it('should remove all listeners', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      emitter.on('event1', listener1);
      emitter.on('event2', listener2);

      emitter.removeAllListeners();

      expect(emitter.listenerCount('event1')).toBe(0);
      expect(emitter.listenerCount('event2')).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle listener errors gracefully', () => {
      const errorListener = () => {
        throw new Error('Test error');
      };
      const normalListener = jest.fn();

      emitter.on('test-event', errorListener);
      emitter.on('test-event', normalListener);

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      emitter.emit('test-event', 'data');

      expect(normalListener).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });
});
