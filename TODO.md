# TODO — Evidence-based Redesign of AI Endpoint Scanner

## Phase 0: Schemas + shared contracts
- [ ] Create `models/` (or `schemas/`) with data model helper utilities
  - Asset model: `{category, subtype, confidence, evidence}`
  - Endpoint occurrence model
  - Secret candidate model
  - Potential issue model
  - Verified finding model
  - Evidence model
- [ ] Add confidence + severity frameworks in shared module

## Phase 1: URL normalization & dedup
- [ ] Implement `normalizeUrl(url)` in a shared module
  - remove timestamps/cachebusters/utm_*/fbclid/gclid/nonces
  - canonicalize remaining query params
- [ ] Add `endpointKey = method + ' ' + normalizedPath`
- [ ] Update `background.js` endpoint registration to store occurrences by endpointKey
- [ ] Update storage layout to include normalized endpoint entries + occurrence counts

## Phase 2: Asset inventory layer (inventory only; no vuln severities)
- [ ] Update `background.js` to create Assets (categories/subtypes)
- [ ] Update `content.js` to emit assets + secret candidates with evidence/confidence fields
- [ ] Keep old fields populated in parallel to avoid breaking the popup

## Phase 3: Endpoint intelligence + auth analysis (validation prerequisites)
- [x] Added normalization+dedupe aggregation groundwork (Phase 1/2) to reduce noise
- [ ] Add endpoint intelligence classification using method/headers/body/response hints
- [ ] Add auth behavior capture (401/403/200) where feasible


## Phase 4: Evidence extraction
- [ ] Implement response intelligence engine and structured evidence objects

## Phase 5: Secret detection expansion
- [ ] Implement secret detection across expanded provider types
  - entropy scoring + redaction

## Phase 6: Validation → verified findings
- [ ] Implement validation workflow gating findings
- [ ] Produce verified findings only when evidence passes validation

## Phase 7: AI security module redesign
- [ ] Replace indicator-based probe verdicts with validation matrix + confidence

## Phase 8: Reporting engine redesign
- [ ] Update `report-generator.js` to report Assets / Potential Issues / Verified Findings
- [ ] Update popup rendering + risk badge to use impact-based severity

## Final: Migration & cleanup
- [ ] Ensure legacy UI fields still render or are removed safely
- [ ] Run lint/tests

