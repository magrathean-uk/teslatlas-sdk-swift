# Security Review: teslatlas-sdk-swift

## Scope

Offline static Standard security audit of retired Teslatlas Swift SDK at eee7e1de.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_f5581d31da7d5b35505f91fa4f265fdb1e548655a8893466a6132aa3abe3d18b
- Revision: eee7e1dee991e2da29bc2b378d1b4a22c7a40d82
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: AGENTS.md, .github/SECURITY.md, Package.swift, Sources/TeslatlasCurrentHub, Sources/TeslatlasHubV1Compatibility, Sources/TeslatlasHubSDK, Sources/CurrentHubCurlShim/CurrentHubCurlShim.c, Selected transport and rich-client tests, docs/architecture/overview.md, README.md

Limitations and exclusions:
- No builds, runtime benchmarks, live Hub, network or credentials.
- No current Teslatlas consumer; finding impact is conditional on future or unobserved consumers.
- Full tests/examples and all source lines not exhaustive.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 1 |
| Severity mix | medium: 1 |
| Confidence mix | high: 1 |
| Coverage | partial |
| Validation mode | static_source_trace |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Retired, preserved Swift client SDK with current-Hub and Hub-v1 transport code; no active Teslatlas consumer. A future integrator could provide endpoint/configuration and receive authenticated Hub data.

### Assets

- Pairing bearer, local Hub identity and TLS trust material
- Private vehicle and drive data returned by Hub
- Client host filesystem and process environment
- Correct bound protocol contracts

### Trust Boundaries

- Caller-supplied Hub URL, credentials and pins to URLSession/curl transport
- Remote Hub response and SSE events to Swift decoders/models and client output
- Embedded binding/schema artifacts to runtime contract validation
- SDK API to future independent Apple consumer

### Attacker Capabilities

- Malicious or compromised Hub endpoint may send redirects, malformed/oversized bodies, crafted SSE and error fields
- Local caller may misconfigure URL, token or pin
- Network adversary may try interception or spoofing when transport trust is weak

### Security Objectives

- Protect bearer and private data from off-origin disclosure
- Pin intended Hub TLS identity and reject unsafe redirect/proxy behavior
- Bound response/event processing and parsing
- Avoid logging sensitive values or allowing unsafe file/command execution

### Assumptions

- Archived SDK is not currently consumed by Teslatlas App or another known product; impact is conditional on future integrators.
- Offline static review; no live Hub, credentials, builds, runtime or network.
- Existing source is preserved and must not be edited.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Unbounded rich-array uniqueness check can exhaust client CPU](#finding-1) | medium | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Unbounded rich-array uniqueness check can exhaust client CPU

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The quadratic loop, unbounded array rule and authenticated response path are explicit in source; runtime duration was not measured. |
| Category | uncontrolled_resource_consumption |
| CWE | CWE-407 |
| Affected lines | Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:95, Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:146, Sources/TeslatlasHubSDK/TeslatlasClient.swift:565 |

#### Summary

The retired rich-protocol Swift client validates each `derived_fields` item by searching every preceding item. A compromised or malicious trusted Hub can return a schema-valid data-quality page with many distinct short field names inside the 16 MiB response cap. For 100,000 names, validation performs about five billion equality checks before returning, potentially making a future SDK consumer unresponsive. No current Teslatlas product consumes this archived package.

#### Root Cause

A byte budget is used as a proxy for computational budget, while uniqueItems validation uses a quadratic prefix search on an unbounded array.

**cap** — `Sources/TeslatlasHubSDK/Transport.swift:27-28`

The transport byte cap still permits many distinct short names.

```swift
public static let defaultMaximumResponseBytes = 16 * 1_024 * 1_024
```

**schema** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:145-146`

The `derived_fields` schema has no maximum item count or string length.

```swift
"derived_fields": .array(.string(nil, nil, "^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)*$", nil), nil, nil, true)
```

**loop** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:91-98`

Each distinct item triggers a linear prefix search, yielding quadratic work.

```swift
if unique { for index in items.indices where items[..<index].contains(items[index]) { return false } }
```

#### Validation

Independently traced the rich client response to the schema rule and quadratic loop. 100,000 distinct strings such as f0..f99999 fit comfortably under 16 MiB and require roughly 5 billion comparisons.

Validation method: static_source_trace

**route** — `Sources/TeslatlasHubSDK/TeslatlasClient.swift:310-333`

Public client method fetches and validates the data-quality page.

```swift
public func dataQuality(...) async throws ... return try await get(... representation: "resources.data_quality_page")
```

**cap** — `Sources/TeslatlasHubSDK/Transport.swift:27-28`

The transport byte cap still permits many distinct short names.

```swift
public static let defaultMaximumResponseBytes = 16 * 1_024 * 1_024
```

**schema** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:145-146`

The `derived_fields` schema has no maximum item count or string length.

```swift
"derived_fields": .array(.string(nil, nil, "^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)*$", nil), nil, nil, true)
```

**loop** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:91-98`

Each distinct item triggers a linear prefix search, yielding quadratic work.

```swift
if unique { for index in items.indices where items[..<index].contains(items[index]) { return false } }
```

**dispatch** — `Sources/TeslatlasHubSDK/TeslatlasClient.swift:558-578`

A 200 response reaches rich validation before the typed result is returned.

```swift
let object = try JSONDecoder().decode(TeslatlasJSONValue.self, from: response.body); try RichRepresentationValidator.validate(object, representation: representation)
```

Counterevidence and remaining uncertainty:
- Authenticated HTTPS/origin policy constrains who can supply a response.
- The SDK is retired and not consumed by the current App.
- Response is capped at 16 MiB, but this does not cap CPU to a reasonable amount.

Limitations:
- No build, runtime timing or live Hub execution.

#### Dataflow

The canonical finding records the affected path at Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:95, Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:146, Sources/TeslatlasHubSDK/TeslatlasClient.swift:565, but no expanded source-to-sink narrative was recorded.

- **Source:** Hub response JSON `items[].derived_fields`

- **Sink:** ArraySlice.contains inside uniqueness validator

- **Outcome:** Quadratic equality comparisons

**route** — `Sources/TeslatlasHubSDK/TeslatlasClient.swift:310-333`

Public client method fetches and validates the data-quality page.

```swift
public func dataQuality(...) async throws ... return try await get(... representation: "resources.data_quality_page")
```

**cap** — `Sources/TeslatlasHubSDK/Transport.swift:27-28`

The transport byte cap still permits many distinct short names.

```swift
public static let defaultMaximumResponseBytes = 16 * 1_024 * 1_024
```

**schema** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:145-146`

The `derived_fields` schema has no maximum item count or string length.

```swift
"derived_fields": .array(.string(nil, nil, "^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)*$", nil), nil, nil, true)
```

**loop** — `Sources/TeslatlasHubSDK/RichRepresentationValidator.swift:91-98`

Each distinct item triggers a linear prefix search, yielding quadratic work.

```swift
if unique { for index in items.indices where items[..<index].contains(items[index]) { return false } }
```

**dispatch** — `Sources/TeslatlasHubSDK/TeslatlasClient.swift:558-578`

A 200 response reaches rich validation before the typed result is returned.

```swift
let object = try JSONDecoder().decode(TeslatlasJSONValue.self, from: response.body); try RichRepresentationValidator.validate(object, representation: representation)
```

#### Reachability

The endpoint is authenticated and origin-restricted; the attack is through a trusted but malicious/compromised response.

- **Attacker:** Controller of, or actor able to compromise, the configured trusted Hub response

- **Entry point:** Authenticated rich-protocol `/data-quality` response

- **Outcome:** Client becomes unresponsive or spends excessive CPU validating one response

Preconditions:
- A future consumer uses this retired rich SDK and invokes dataQuality().
- The attacker can supply a valid response from the configured trusted Hub origin, including required headers.

Limitations:
- No current Teslatlas consumer of this archived package is established.
- No runtime benchmark was run; complexity and payload size are source-derived.

#### Severity

**Medium** — A crafted authenticated Hub response can cause substantial client CPU exhaustion, but the SDK is retired and a trusted/configured Hub or its transport must be malicious or compromised.

Lower if the rich client remains permanently unused; raise if an active consumer accepts attacker-influenced Hub responses. A finite per-array budget and linear uniqueness check would remove this path.

#### Remediation

Replace the prefix search with a Set-based linear duplicate check, and impose a finite maximum on `derived_fields`/other unique arrays before validation. Keep the 16 MiB transport budget as a separate defense.

Tests:
- A schema-valid data-quality page containing a large distinct `derived_fields` array is rejected quickly at the item-count budget.
- Duplicate-field rejection remains correct, including nested arrays and value equality.
- Benchmark validation growth at 1k, 10k and 100k entries to rule out quadratic scaling.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Tests and examples | Security contract evidence | Needs follow-up | Relevant tests searched; archived package was not built or executed. |
| Current-Hub transport and pinning | Bearer/TLS/redirect/proxy | No issue found | Default Apple/Linux paths enforce HTTPS, trust, pinning, redirect rejection and bounded responses. |
| Hub-v1 compatibility transport | Legacy auth and URL trust | No issue found | Exact binding, same-origin and default transport controls reviewed. |
| Response, SSE and rich model parsing | Untrusted input resource budgets | Reported | Quadratic unique-array validation is reportable; SSE framing has finite line/event budgets. |
| Binding and local helper paths | Generated contract/file/process safety | No issue found | Binding hash and endpoint admission controls reviewed. |

## Open Questions And Follow Up

- Whether any independent third-party consumer still uses the retired package is unknown.
- Retired SDK not run; full tests/examples and future caller-supplied transports are not exhaustively assessed.
  - Follow-up prompt: Review deferred unit swift-residual-runtime and close its stated proof gap. Paths: Tests, Examples, Sources.
