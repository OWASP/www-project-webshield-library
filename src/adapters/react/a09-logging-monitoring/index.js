import React from "react";

export const SecurityContext = React.createContext({ logger: null, events: null });

export function SecurityProvider({ logger, events, children }) {
  const value = React.useMemo(() => ({ logger, events }), [logger, events]);
  return React.createElement(SecurityContext.Provider, { value }, children);
}

/**
 * Hook exposing logger and event emitter from SecurityProvider.
 */
export function useSecurityMonitoring() {
  return React.useContext(SecurityContext);
}

export function SecurityAlert({ message, level = "warn" }) {
  return React.createElement("div", { role: "alert", "data-level": level }, message);
}