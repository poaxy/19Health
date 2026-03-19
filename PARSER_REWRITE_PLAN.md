# Subscription Parser Rewrite Plan

## Goals

- Reduce complexity in `subscription/parser.go`.
- Isolate concerns for easier testing and maintenance.
- Preserve existing behavior and supported input formats.

## Proposed Modules

1. `SourceLoader`
   - Responsibility: load raw input from URL, file, folder, or inline content.
   - Interface:
     - `Load(source string) ([]byte, error)`
     - `LoadMany(sources []string) ([][]byte, error)`

2. `ContentDecoder`
   - Responsibility: detect and decode base64/plain text JSON and share-link payloads.
   - Interface:
     - `Decode(raw []byte) (DecodedContent, error)`

3. `LinkParser`
   - Responsibility: parse protocol links (`vmess`, `vless`, `trojan`, `ss`) into intermediate structs.
   - Interface:
     - `ParseLinks(text string) ([]ParsedLink, error)`

4. `OutboundMapper`
   - Responsibility: convert decoded/intermediate records into `models.ProxyConfig`.
   - Interface:
     - `Map(item ParsedLink) (*models.ProxyConfig, error)`

5. `Validator`
   - Responsibility: validate and normalize `ProxyConfig` (stable ID generation, defaults, cleanup).
   - Interface:
     - `NormalizeAndValidate(cfg *models.ProxyConfig) error`

## Refactor Sequence

1. Extract pure helper functions first (no behavior change).
2. Introduce interfaces and constructor-based dependency wiring.
3. Move network/file access behind loader interfaces for unit tests.
4. Add table-driven tests with `testdata/` fixtures for each input format.
5. Replace old parser entry points with orchestration using new modules.
6. Keep compatibility wrappers until migration is complete.

## Test Plan

- Table-driven tests for:
  - URL/file/base64/raw parsing paths.
  - malformed inputs.
  - mixed valid/invalid source batches.
- Golden tests for representative proxy outputs.
- Regression set from existing real-world subscriptions.

## Acceptance Criteria

- Existing public parser behavior remains backward-compatible.
- Parser package has focused files with clear responsibilities.
- Unit coverage added for every module with no network dependency.
