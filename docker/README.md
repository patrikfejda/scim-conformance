# Test targets

Compose files for running the suite against real identity providers locally.

## Keycloak (native SCIM, experimental since 26.6)

```
docker compose -f keycloak.yml up -d
```

Then enable a SCIM client/token in the admin console (http://localhost:8080, admin/admin) and run:

```
scim-conformance --base-url http://localhost:8080/realms/master/scim/v2 --token $TOKEN
```

NOTE: the exact feature-flag name and SCIM base path of Keycloak's native
SCIM are still moving between 26.x releases — verify against the release
notes of the version you run before filing findings upstream.

## authentik

authentik's SCIM support is provider-direction (outbound provisioning), which
is a target for the planned client-testing mode rather than this server
runner. Tracked in the roadmap.
