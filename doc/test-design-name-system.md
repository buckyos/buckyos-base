# Test Case Design: name-client and name-lib

Version: 1.0
Status: Draft
Scope: `src/name-client`, `src/name-lib`
Language: English (ASCII)

## 1. Goals
- Provide a complete, structured test plan for the name system core crates.
- Capture already implemented tests and identify missing coverage.
- Prioritize correctness, trust-level logic, caching behavior, and DNS TXT parsing.

## 2. In-Scope Components
### name-lib
- DID parsing and host name conversions.
- EncodedDocument parsing and did-doc decoding.
- ZoneBootConfig and ZoneConfig logic (JWT encode/decode, OOD parsing).
- OwnerConfig, DeviceConfig, DeviceMiniConfig, DeviceInfo, DeviceMiniInfo.
- Utility crypto helpers and key derivation.

### name-client
- NameClient and NameQuery orchestration.
- DIDDocumentCache (Filesystem and SQLite backends).
- Provider contract and NameInfo TXT parsing.
- DNS provider behavior and query flow.
- Local/BNS/HTTPS providers (planned coverage).

## 3. Existing Tests (Implemented)
The following tests are currently implemented in crate modules. This list is intended to anchor the design to current coverage.

### name-lib
- `src/name-lib/src/lib.rs`
  - `test_utility`: `is_did` positive/negative.
  - `test_get_device_info`: `DeviceInfo::auto_fill_by_system_info` smoke.
- `src/name-lib/src/did.rs`
  - `test_did_from_str`: DID parsing, host name conversion, bridge mapping, path extraction.
  - `test_encoded_document_from_str_detects_format`: JsonLd vs JWT detection.
  - `test_parse_did_doc_routes_by_shape`: Owner/Device/Zone routing.
- `src/name-lib/src/zone.rs`
  - Extensive `OODDescriptionString` parsing/serialization tests (OOD/Gateway/OODOnly, error cases, round-trip).
  - Helper routines in tests for ZoneBootConfig creation and related fixtures.
  - `test_zone_config_encode_decode`: ZoneConfig JWT encode/decode and auth key.
- `src/name-lib/src/user.rs`
  - `test_owner_config`: encode/decode round-trip with Ed25519 keys.
  - `new_by_pkx_*`: pkx validation and error cases.
- `src/name-lib/src/device.rs`
  - `test_device_mini_info`, `test_device_info`: auto-fill system info.
  - `test_device_mini_config`: mini-config JWT encode/decode and round-trip.
  - `test_device_config`: DeviceConfig encode/decode and DeviceInfo round-trip.
- `src/name-lib/src/utility.rs`
  - `test_generate_x25519_key_pair_share_secret`.
  - `test_generate_ed25519_key_pair`.
  - `test_generate_ed25519_key_pair_from_mnemonic_print`.
  - `test_decode_jwt_claim_without_verify_rejects_invalid`.
  - `test_from_pkcs8_rejects_invalid_data`.

### name-client
- `src/name-client/src/lib.rs`
  - `test_resolve_did_nameinfo`: mock provider + cache path resolves did.
- `src/name-client/src/name_client.rs`
  - Cache priority rules and fallback logic (prefer high trust, cache on errors, disabled removes cache, cache reuse).
  - `resolve_did_web_normalizes_to_host_name`.
- `src/name-client/src/name_query.rs`
  - Trust-level ordering, iat selection, max trust filter, disabled short-circuit.
  - `error_when_no_providers_configured`.
- `src/name-client/src/doc_cache.rs`
  - FS cache insert/get/expire, update rules (trust/iat), missing meta handling.
  - SQLite cache round-trip.
  - `fs_update_does_not_replace_named_obj`.
- `src/name-client/src/dns_provider.rs`
  - DNS A/TXT query + DID resolution smoke test (integration with network).
- `src/name-client/src/provider.rs`
  - TXT <-> DID document parsing, round-trip and error cases.

## 4. Coverage Matrix (Implemented vs Planned)
Legend: [x] Implemented, [ ] Planned

### name-lib
- DID parsing and host name mapping [x]
- DID bridge config handling [x]
- EncodedDocument JsonLd/JWT detection [ ]
- EncodedDocument JsonLd/JWT detection [x]
- parse_did_doc routing (Owner/Device/Zone) [x]
- ZoneBootConfig encode/decode (JWT + JsonLd) [x]
- ZoneConfig encode/decode + key selection [x]
- OODDescriptionString parsing and serialization [x]
- OwnerConfig new_by_pkx validation [x]
- OwnerConfig encode/decode round-trip [x]
- DeviceConfig encode/decode round-trip [x]
- DeviceMiniConfig JWT round-trip [x]
- DeviceInfo and DeviceMiniInfo auto-fill [x]
- Utility key load and pkcs8 parsing error cases [x]
- Mnemonic-based key derivation determinism [x] (prints only, assertions minimal)

### name-client
- NameQuery trust ordering and iat selection [x]
- NameQuery max trust filtering [x]
- NameQuery disabled short-circuit [x]
- NameQuery error when no providers [x]
- NameClient cache fallback on provider errors [x]
- NameClient cache purge on Disabled [x]
- DIDDocumentCache FS insert/update/expire [x]
- DIDDocumentCache named object update rule [x]
- DIDDocumentCache SQLite insert/update/expire [x]
- NameInfo TXT parsing (BOOT/PKX/DEV) [x]
- DNS provider query and did resolution (live network) [x]
- LocalNsProvider behavior [ ]
- BnsProvider behavior [ ]
- HttpsProvider and SmartProvider behavior [ ]
- Cloudflare provider (feature gated) [ ]

## 5. Planned Test Design by Module

### 5.1 name-lib
#### DID
- Invalid DID strings (missing method/id, bad prefixes).
- Host name conversion with empty/edge bridge configs.
- `get_auth_key` and `get_ed25519_auth_key` for dev DIDs.

#### EncodedDocument and parse_did_doc
- JsonLd vs JWT detection for `EncodedDocument::from_str`.
- parse_did_doc routes to OwnerConfig/DeviceConfig/ZoneConfig correctly.
- Error when no recognized markers present.

#### ZoneBootConfig and ZoneConfig
- Encode/decode with and without public key verification.
- `device_is_ood`, `device_is_gateway`, `get_gateway_name` on mixed OOD lists.
- `select_same_subnet_ood` and `select_wan_ood` selection behavior with multiple OODs.
- `get_auth_key` and `get_exchange_key` behavior when missing keys.

#### OwnerConfig
- `set_default_zone_did` adds service endpoint correctly.
- Decode error handling with invalid JWT or invalid JWK.

#### DeviceConfig, DeviceInfo, DeviceMiniConfig
- `new_by_mini_config` populates id/owner/zone correctly.
- `get_exchange_key` and `get_auth_key` for missing kid or missing keys.
- `is_wan_device` behavior across `net_id` values.
- Auto-fill error handling when system info collection fails (mock system calls).

#### Utility
- `decode_jwt_claim_without_verify` rejects malformed tokens.
- `from_pkcs8` header and length validation.
- `load_private_key` and `load_raw_private_key` error paths for invalid PEM.
- `generate_ed25519_key_pair_from_mnemonic` deterministic outputs on known vectors.

### 5.2 name-client
#### NameClient
- `resolve` did:web normalization to host name.
- `resolve_did` behavior with doc_type filters.
- Cache update rules on trust level (lower number is higher trust).
- Cache bypass when disabled errors occur.

#### NameQuery
- No providers configured returns clear error.
- Parallel queries within same trust level choose max iat.
- ensure `max_trust_level` strictly blocks lower priority results.

#### DIDDocumentCache
- FS backend: meta file corruption handling.
- DB backend: constraint errors and malformed doc handling.
- Update rules for named object DID (if `is_named_obj_id`).

#### NameInfo TXT parsing
- Multiple TXT segments for BOOT/PKX/DEV concatenation order.
- Invalid BOOT/DEV JWT records should be ignored and preserved as TXT.
- Round-trip for TXT-only NameInfo.

#### Providers
- DnsProvider: TXT lookup error handling and TTL propagation.
- BnsProvider: query + query_did with mock server (contract stub).
- HttpsProvider: `.well-known` paths and doc_type resolution.
- LocalNsProvider: local cache or file-based resolution behavior.
- SmartProvider: provider selection and fallback behavior.
- Cloudflare provider (feature `cloudflare`): CRUD operations if supported.

## 6. Test Types and Strategy
- Unit tests: data structure correctness, parsing, encoding/decoding.
- Integration tests: provider flow with mocks or local fixtures.
- Network tests: DNS queries (guarded or ignored in CI if unstable).
- Property tests (planned): OODDescriptionString round-trip and DID conversions.
- Fuzz tests (planned): TXT record parsing robustness.

## 7. Test Data and Fixtures
- Deterministic Ed25519 keys (existing PEM/JWK fixtures in tests).
- Static DID samples: `did:web:example.com`, `did:bns:alice`, `did:dev:<pkx>`.
- TXT record fixtures containing `BOOT=`, `PKX=`, `DEV=`.
- Temporary directories for FS/SQLite caches.

## 8. Priorities
P0:
- DID parsing and TXT parsing correctness.
- Trust-level selection and cache update rules.
- Cache expiration/refresh behavior.

P1:
- Provider-specific integration behavior (DNS/HTTPS/BNS).
- ZoneConfig and DeviceConfig encode/decode error handling.

P2:
- Property/fuzz tests, performance and concurrency stress.

## 9. Gaps and Risks
- Live network tests (DNS) can be flaky; plan for isolated fixtures.
- Some tests currently print output rather than assert; add assertions for deterministic validation.
- Provider coverage outside DNS is missing; prioritize mockable integration tests.

## 10. Proposed File Layout (Documentation)
- This document: `doc/test-design-name-system.md`
- Optional follow-ups:
  - `doc/test-design-name-lib.md`
  - `doc/test-design-name-client.md`
