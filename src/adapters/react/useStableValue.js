import React from "react";

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Structural equality for plain objects and arrays; everything else (functions,
// class instances, RegExps) is compared by identity.
function deepEqual(a, b) {
  if (Object.is(a, b)) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && deepEqual(a[key], b[key]));
  }
  return false;
}

/**
 * Returns the previous value while the new one is structurally equal, so hooks
 * can memoize on config objects written inline (`useSafeFetcher({})`) instead of
 * rebuilding their instance on every render. Internal to the React adapter.
 */
export function useStableValue(value) {
  const ref = React.useRef(value);
  if (!deepEqual(ref.current, value)) {
    ref.current = value;
  }
  return ref.current;
}
