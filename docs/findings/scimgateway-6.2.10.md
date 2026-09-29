# Findings: scimgateway 6.2.10 (plugin-loki)

Target: `scimgateway` 6.2.10 from npm, default `plugin-loki` (in-memory) configuration, Bun runtime, basic auth. Run date: 2026-09-29.

Result: 22/23 checks pass, 1 finding. Verified manually beyond the runner.

## Finding: attribute names in filters are case-sensitive

RFC 7644 §3.4.2.2: "Attribute names and attribute operators used in filters are case insensitive."

```
POST /Users {"schemas":[...], "userName":"case-test"}        -> 201

GET /Users?filter=userName eq "case-test"                    -> totalResults: 1
GET /Users?filter=username eq "case-test"                    -> totalResults: 0   (!)
GET /Users?filter=userName EQ "case-test"                    -> totalResults: 1   (operator case OK)
```

The lowercase attribute name silently returns an empty ListResponse instead of matching. Operators are handled case-insensitively; attribute names are not.

Why it matters: provisioning clients vary in casing (and per RFC are allowed to). A silent empty result is worse than an error — an IdP checking "does this user exist?" before create will conclude no and provision a duplicate.

## Reproduction

```
npm install scimgateway   # scaffolds index.ts + config/plugin-loki.json
bun index.ts              # listens on :8880, basic auth gwadmin/password
scim-conformance --base-url http://localhost:8880 --basic gwadmin:password
```

The failing check is `user-filter-caseinsensitive`.
