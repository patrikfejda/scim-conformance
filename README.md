# scim-conformance

A vendor-neutral, black-box conformance test runner for SCIM 2.0 (RFC 7643/7644) service providers. Single static binary, CI-friendly, no framework assumptions about the server under test.

**Status: early prototype.** This is the first slice of a larger plan: a language-agnostic conformance suite covering the 2025/26 SCIM RFCs (9865 cursor pagination, 9967 events, 9944 device schema) and the IPSIE lifecycle profiles, a client/provisioner testing mode, and a public interop matrix across open-source identity providers. A funding application for the full roadmap is being prepared for the NLnet Restack Fund; this repository exists so the plan is judged on running code.

## Why

Microsoft's SCIM validator tests Entra compatibility. Okta's tests test Okta compatibility. WSO2's suite is frozen. Meanwhile, open-source SCIM implementations are arriving right now (Keycloak native SCIM, Zitadel, Univention Nubus) and every IdP↔app pair still gets debugged bilaterally, because there is no shared, neutral test oracle. This project aims to be that oracle.

## Usage

```
go install github.com/patrikfejda/scim-conformance/cmd/scim-conformance@latest

scim-conformance --base-url https://idp.example/scim/v2 --token $SCIM_TOKEN
scim-conformance --base-url http://localhost:8080/scim/v2 --basic admin:admin --json
```

Exit code is non-zero when a **required** check fails, so it drops straight into CI. Checks where the spec is ambiguous or near-universally violated in the wild (for example plain `application/json` content types) are **advisory**: they are reported, never fatal, and will feed a machine-readable deviation corpus.

## Current checks

| Group | Checks |
|---|---|
| Discovery (RFC 7644 §4) | ServiceProviderConfig presence + schema, mandatory capability declarations, media type, /Schemas, /ResourceTypes |
| User lifecycle (RFC 7644 §3) | spec-minimal create (advisory) with enriched fallback, create (201 + id), read, 404 error shape (§3.12), filter `eq`, case-insensitive filter attribute names (§3.4.2.2), no-match filter as empty ListResponse, list-all shape, pagination (`startIndex`/`itemsPerPage` presence, `count` bound, §3.4.2.4), `attributes` selection (§3.4.2.5, advisory), PUT replace verified via GET, write-echo persistence (advisory), PATCH replace verified via GET, PATCH add on multi-valued `emails` (§3.5.2.1), PATCH replace via value filter path `emails[type eq "work"].value` (§3.5.2), delete + delete verification |

Writes are never trusted from their responses alone: PUT and PATCH results are verified with a follow-up GET, which is how the suite catches attributes that are echoed back but silently dropped.

Run `go test ./...` — every check is tested against a compliant in-memory SCIM server plus broken variants proving the check detects its target violation.

## First results

**Live interop matrix: https://patrikfejda.github.io/scim-conformance/matrix/** — rendered by `matrix-gen` from the JSON reports in [docs/matrix](docs/matrix). Regenerate with:

```
scim-conformance --base-url ... --json > docs/matrix/<impl>.json
go run ./cmd/matrix-gen -o docs/matrix/index.html "Name=docs/matrix/<impl>.json" ...
```

| Implementation | Result | Findings |
|---|---|---|
| Keycloak 26.7.4 native SCIM (preview) | 21/23 pass, 2 advisory findings | [/Schemas contradicts enforced user-profile requirements + wrong `scimType`; `displayName` echoed in write responses but silently dropped](docs/findings/keycloak-26.7.4.md) |
| scim2-server 0.3.0 (Yaal Coop) | 23/23 pass | clean run — no deviations observed in the current check set |
| scimgateway 6.2.10 (plugin-loki) | 22/23 pass, 1 finding | [attribute names in filters are case-sensitive; lowercase `username` silently returns an empty result](docs/findings/scimgateway-6.2.10.md) |

All findings are verified manually beyond the runner before being written up; upstream reports are being prepared.

## Roadmap

- More RFC 7644 coverage: PATCH on multi-valued attributes, filter grammar corners, `excludedAttributes`, pagination
- RFC 9865 (cursor pagination), RFC 9967 (SCIM events over SET), RFC 9944 (device schema) test packs
- Client/provisioner testing mode (scripted mock server + wire-log assertions)
- Public interop matrix: Keycloak native SCIM, authentik, Zitadel, Univention Nubus, scimgateway, …
- Machine-readable deviation corpus with per-implementation quirk flags

## Development notes

Parts of this codebase are developed with AI assistance (Claude); all code is reviewed, tested and maintained by the author. AI-assisted commits carry a `Co-Authored-By` trailer.

## License

MIT — see [LICENSE](LICENSE).
