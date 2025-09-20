export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "PATCH"
  | "HEAD"
  | "OPTIONS"
  | "*";

export type ConditionType =
  | "role"
  | "ip"
  | "time"
  | "rate"
  | "header"
  | "query"
  | "custom";
