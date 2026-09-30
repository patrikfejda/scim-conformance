# Findings: Keycloak 26.7.4 native SCIM (preview, `scim-api:v1`)

Target: `quay.io/keycloak/keycloak:26.7` (26.7.4), `start-dev`, `KC_FEATURES=scim-api`, realm created with `scimApiEnabled=true`, service-account client with `manage-users` + `view-realm` and an audience mapper adding the SCIM base URL (`.../realms/<realm>/scim/v2`) as token audience. Run date: 2026-09-28.

Result: 13 checks pass, 2 findings. Both verified manually with curl in addition to the runner.

## Finding 1: user-profile requirements contradict the published /Schemas

`POST /Users` with a spec-minimal user (`userName` only — the sole required core attribute per RFC 7643 §4.1) is rejected:

```
400 {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],
     "status":"400","scimType":"invalidSyntax","detail":"Please specify lastName."}
```

Adding `name` gets a second rejection: `"Please specify email."` The realm's default user-profile policy (firstName/lastName/email required) is enforced through SCIM — while the same server's `GET /Schemas` declares for the User schema:

```
userName  required=True
name      required=False
emails    required=False
```

Two sub-issues:

1. **Schema honesty:** a SCIM client discovering the service via `/Schemas` (the mechanism RFC 7644 §4 provides for exactly this) is told `name` and `emails` are optional, then fails at runtime. The user-profile requirements should be reflected in the published schema (`required=true`), or not enforced for SCIM-created users.
2. **Wrong `scimType`:** RFC 7644 §3.12 defines `invalidSyntax` as "the request body message structure was invalid" — the message here is structurally perfect. A missing required value is `invalidValue`.

## Finding 2: `displayName` is echoed in write responses but silently dropped

`displayName` is declared in `/Schemas` (`required=False`) and accepted by both `POST` and `PUT` — the PUT response even echoes it back:

```
PUT /Users/{id} {"...", "displayName": "Put Name"}  -> 200, body contains "displayName": "Put Name"
GET /Users/{id}                                     -> 200, displayName ABSENT
```

`PATCH` with `{"op":"replace","path":"displayName","value":...}` likewise returns 200 and changes nothing, while the same PATCH on `name.givenName` works (control test). RFC 7644 §3.5.1 requires the PUT response to "contain the updated resource" — echoing an attribute that was not stored misrepresents resource state, and clients performing write-read verification will see silent data loss.

Options upstream: persist the attribute, reject writes to it with `400`/`invalidValue`, or at minimum stop echoing it and remove it from the published schema.

## Finding 3: PATCH-adding group members returns 200 but is silently ignored — while PUT honestly rejects the same operation

Group membership management on updates is not supported by the preview SCIM API, but the two update verbs surface this inconsistently (verified 2026-09-30):

```
PATCH /Groups/{id} {"Operations":[{"op":"add","path":"members","value":[{"value":"<userId>"}]}]}
-> 200 OK (response body: the group, without members)
GET /Groups/{id}
-> 200, members ABSENT

PUT /Groups/{id} {"...", "members":[{"value":"<userId>"}]}
-> 400 {"scimType":"invalidSyntax","detail":"Managing members on updates is not supported"}
```

The server demonstrably knows the limitation — PUT says so — yet PATCH reports success and drops the operation. Group membership propagation is the core joiner–mover–leaver use case: a provisioning IdP that PATCHes memberships receives 200 and assumes success, silently desynchronizing group state. (Also: `invalidSyntax` on the PUT is again the wrong `scimType` for an unsupported-operation condition; RFC 7644 §3.12 offers `mutability`/`invalidValue`.)

Expected: PATCH on `members` should return the same explicit 400 (or be implemented), and `/ServiceProviderConfig`/`/Schemas` should reflect the limitation.

## Reproduction

```
docker compose -f docker/keycloak.yml up -d
docker exec docker-keycloak-1 /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin
docker exec docker-keycloak-1 /opt/keycloak/bin/kcadm.sh create realms \
  -s realm=scimtest -s enabled=true -s scimApiEnabled=true
docker exec docker-keycloak-1 /opt/keycloak/bin/kcadm.sh create clients -r scimtest \
  -s clientId=scim-client -s serviceAccountsEnabled=true -s publicClient=false -s secret=secret
# grant service-account roles manage-users + view-realm (realm-management),
# add an audience protocol mapper with included.custom.audience = http://localhost:8080/realms/scimtest/scim/v2
scim-conformance --base-url http://localhost:8080/realms/scimtest/scim/v2 --token $TOKEN
```

Note: the audience requirement itself (token `aud` must contain the SCIM base URL, checked in `ScimRealmResourceFactory`) is undocumented in the feature announcement and produces a bare `401 Invalid token audience` — documentation-issue material as well.
