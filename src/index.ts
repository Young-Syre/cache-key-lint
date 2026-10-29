/** Library entry point. The CLI is a thin wrapper over these exports. */

export { analyse, redactReport, sortFindings, type AnalyseOptions } from './analyse.js';
export { CaptureError, mergeCaptures, parseCapture, type LoadResult } from './capture.js';
export {
  formatCacheHeaders,
  formatDelimiters,
  formatNormalisers,
  formatPlan,
  formatPlanMarkdown,
  formatPlanText,
  formatReport,
  formatReportMarkdown,
  formatReportText,
  formatRules,
  severityCounts,
  type Format,
} from './format.js';
export {
  anyHit,
  cacheObservations,
  groupByResource,
  pairs,
  requestDelta,
  responseDelta,
  type CacheObservation,
  type RequestDelta,
  type ResourceGroup,
  type ResponseDelta,
} from './group.js';
export {
  CACHE_STATUS_HEADERS,
  CREDENTIAL_HEADERS,
  ROUTING_HEADERS,
  foldHeaders,
  headerValue,
  isHitValue,
  makeHeader,
  parseCookieHeader,
  parseVary,
  setCookieNames,
} from './headers.js';
export {
  IDENTITY_MARKERS,
  describeIdentity,
  hasProof,
  identitySignals,
  isUserSpecific,
  type IdentitySignal,
} from './identity.js';
export { inferKey, inferKeys } from './key.js';
export {
  DEFAULT_NORMALISERS,
  NormaliserSet,
  parseNormaliserConfig,
  type Normaliser,
} from './normalise.js';
export { BUSTER_PARAM, CACHE_BUSTER_WARNING, buildPlan } from './plan.js';
export {
  HEURISTICALLY_CACHEABLE_STATUSES,
  ageSeconds,
  directiveSeconds,
  parseDirectives,
  requestAuth,
  storability,
  type Directives,
  type RequestAuth,
  type Storability,
} from './policy.js';
export { CREDENTIAL_QUERY_PARAMS, REDACTED, Redactor } from './redact.js';
export { RULES, rule, ruleIds, type RuleMeta } from './rules/catalogue.js';
export {
  DELIMITERS,
  STATIC_EXTENSIONS,
  STATIC_PREFIXES,
  cacheVisibleExtension,
  canonicalQuery,
  decodeOnce,
  delimiterSplits,
  looksStaticToCache,
  originCandidates,
  parseQuery,
  parseUrl,
  resolveDotSegments,
  serialiseQuery,
  type Delimiter,
  type ParsedUrl,
  type QueryParam,
} from './url.js';
export { TOOL, VERSION } from './version.js';
export * from './types.js';
