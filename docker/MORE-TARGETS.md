# More test targets

Candidate open-source SCIM 2.0 **servers** to add to the interop matrix, each runnable
locally with minimal fuss. Research date: 2026-09-30.

Legend:
- **server-testable** — real inbound SCIM 2.0 server; point `scim-conformance --base-url ...` at it.
- **client-testable** — outbound SCIM provisioner; point it at `scim-mockserver` instead.

## Ranking by ease (time-to-running as a testable SCIM server)

| # | Target | Type | Server-testable | Effort | Notes |
|---|--------|------|-----------------|--------|-------|
| 1 | **i2scim** (memory, security off) | Java/Quarkus | Yes | ~5 min, one `docker run` | Full CRUD incl. Groups, endpoints at root `/` |
| 2 | **scim2-server 0.3.0** (already in matrix) | Python | Yes | ~2 min | Confirmed latest; `/v2/` base |
| 3 | **Zitadel** (SCIM preview) — **priority** | Go | Yes | ~15 min | Real product; Users only (no Groups), `count` max 100 |
| 4 | **limosa-io/laravel-scim-server** | PHP/Laravel | Yes | ~5 min | Backend of scim.dev playground; verify auth/base path live |
| 5 | **authentik** (SCIM *source* = inbound) | Python | Partial | ~10 min | Provisioning-oriented; read/filter/pagination unconfirmed. Also client-testable via SCIM *provider* |
| 6 | **SCIMple** (Apache Directory) | Java/Spring | Yes, but stale image | risky | Only ready image is `tirasa/scimple-server`, ~2 yrs old, amd64-only |

Skip: WSO2 Charon (library, ships only inside full WSO2 IS — too heavy); Go libs
`elimity-com/scim`, `di-wu/scim`, `scim2/example-server` (libraries/stubs, no runnable
server); `suvera/scim2-server` (does not exist — suvera ships test tooling, not a server);
midPoint (SCIM via connector — too heavy).

---

## 1. i2scim (independentid) — easiest full-featured new target

Real inbound SCIM 2.0 (RFC 7644) server. Use the **universal** image with the in-memory
provider (no Mongo/LDAP) and security off for a clean anonymous full-CRUD run.

> Note: the old `independentid/i2scim-mem` image is archived (~5 yrs old). Use
> `independentid/i2scim-universal` and select the backend via `scim.prov.providerClass`.

```bash
docker run -d --name i2scim -p 8080:8080 \
  -e "scim.prov.providerClass=com.independentid.scim.backend.memory.MemoryProvider" \
  -e "scim.prov.memory.dir=/scim/data" \
  -e "scim.prov.memory.file=scimdb.json" \
  -e "scim.event.enable=false" \
  -e "scim.security.enable=false" \
  -v i2scim_data:/scim \
  independentid/i2scim-universal:latest
```

Wait for readiness (Quarkus): `curl -sf http://localhost:8080/q/health/ready`.

**SCIM base URL:** endpoints are at the **root** — no `/scim/v2` prefix.
Base URL for the runner is `http://localhost:8080`.
(`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, `/Users`, `/Groups`)

```bash
scim-conformance --base-url http://localhost:8080 --json > docs/matrix/i2scim.json
```

**Auth:** with `scim.security.enable=false` there is none (anonymous R/W). To test with
auth instead, use HTTP Basic with the default root user `admin` / `admin`:

```bash
docker run -d --name i2scim -p 8080:8080 \
  -e "scim.prov.providerClass=com.independentid.scim.backend.memory.MemoryProvider" \
  -e "scim.prov.memory.dir=/scim/data" \
  -e "scim.security.enable=true" \
  -e "scim.security.authen.basic=true" \
  -e "scim.security.root.enable=true" \
  -e "scim.security.root.username=admin" \
  -e "scim.security.root.password=admin" \
  -v i2scim_data:/scim \
  independentid/i2scim-universal:latest
# scim-conformance --base-url http://localhost:8080 --basic admin:admin
```

**Gotchas:**
- Default ACIs (when security is ON): discovery (`/ServiceProviderConfig`, `/ResourceTypes`,
  `/Schemas`) is unauthenticated; `/Users` `/Groups` read needs role `user|bearer|root`;
  add/modify/delete needs `admin`/`root`. A full-CRUD conformance run therefore needs
  `admin:admin` (or just security off).
- No config files need mounting — schema/resourceTypes/ACIs are baked into the universal image.
- Memory provider is single-node and flushes periodically to `/scim/data`; use `docker rm -v`
  between runs for a clean slate, or drop the volume for ephemeral data.

Sources:
- https://github.com/i2-open/i2scim
- https://hub.docker.com/r/independentid/i2scim-universal
- https://github.com/i2-open/i2scim/blob/master/docker-compose-signals.yml (runnable template)
- https://i2scim.io/Configuration.html , https://i2scim.io/AccessControl.html
- https://github.com/i2-open/i2scim/blob/master/i2scim-server/k8s/memory/1-i2scim-memory-configs.yaml (root admin/admin)
- https://github.com/i2-open/i2scim/blob/master/config/scim/schema/default-acis.json

---

## 2. scim2-server 0.3.0 (Yaal Coop / python-scim) — already in matrix

Confirmed: **0.3.0 (released 2026-09-28) is the latest** — nothing newer exists. The repo
moved to the `python-scim` GitHub org.

```bash
docker run --publish 8080:8080 ghcr.io/python-scim/scim2-server --bearer-token secret
# or: pip install scim2-server && scim2-server --bearer-token secret --hostname 0.0.0.0 --port 8080
```

**SCIM base URL:** `http://localhost:8080/v2/` (`/v2/ServiceProviderConfig`, `/v2/Users`, `/v2/Groups`, ...)
**Auth:** `Authorization: Bearer secret`. Without `--bearer-token` it runs anonymously.

```bash
scim-conformance --base-url http://localhost:8080/v2 --token secret
```

Sources: https://github.com/python-scim/scim2-server , https://pypi.org/project/scim2-server/

---

## 3. Zitadel — SCIM v2.0 (Preview) — PRIORITY target

Real inbound SCIM 2.0 server, shipped as a **Preview** feature. It is org-scoped: the base
URL contains the organization ID. Runnable locally in ~15 min (compose + one service user + PAT).

### 3.1 Run locally via the official docker-compose

```bash
curl -fsSLO https://raw.githubusercontent.com/zitadel/zitadel/main/deploy/compose/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/zitadel/zitadel/main/deploy/compose/.env.example
cp .env.example .env
# masterkey must be exactly 32 chars
echo "ZITADEL_MASTERKEY=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)" >> .env
docker compose up -d --wait
```

For plain-HTTP local use the compose defaults already set `ZITADEL_EXTERNALSECURE=false`,
`ZITADEL_EXTERNALDOMAIN=localhost`, `ZITADEL_EXTERNALPORT=8080`, `ZITADEL_TLS_ENABLED=false`.
The compose file bundles the required Postgres/Cockroach DB.

**Console:** http://localhost:8080/ui/console
**Default admin:** `zitadel-admin@zitadel.localhost` / `Password1!`

> Gotcha: `ExternalDomain`/`ExternalPort`/`ExternalSecure` must match how you actually reach
> Zitadel (here `localhost:8080`, http), otherwise issued tokens fail audience/issuer validation.

### 3.2 Create a service user + Personal Access Token (PAT)

In the console:
1. **Organization → Users → New → Service User** (a machine user). Set Access Token Type = `Bearer`.
2. Open the service user → **Personal Access Tokens → New** → (optional expiry) → **Add**.
   Copy the token immediately — it is shown only once.
3. Grant the service user the **Org User Manager** manager role (Organization → Managers, or
   on the user). Per the Okta guide this is sufficient — no higher role is required.

The token is sent as `Authorization: Bearer <PAT>`.

### 3.3 Find the organization ID (needed in the SCIM path)

The org ID is a resource ID visible on the Organization detail page in the console, or fetch
it with the PAT:

```bash
curl -s http://localhost:8080/management/v1/orgs/me \
  -H "Authorization: Bearer $PAT" | jq -r '.org.id'
```

### 3.4 SCIM endpoint and base URL

**Exact base URL shape:** `http://${DOMAIN}/scim/v2/{orgId}` — the orgId is **required** in the path.
(Cloud example from the docs: `https://test-domain-bkeog4.us1.zitadel.cloud/scim/v2/322355063156684166`.)

Supported endpoints: `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`, `/Users`
(full CRUD), `POST /Users/.search`, `POST /Bulk` (max 100 ops).

```bash
ORG_ID=$(curl -s http://localhost:8080/management/v1/orgs/me -H "Authorization: Bearer $PAT" | jq -r '.org.id')
scim-conformance --base-url "http://localhost:8080/scim/v2/$ORG_ID" --token "$PAT" --json > docs/matrix/zitadel.json
```

**Preview limitations to expect in the run:**
- Only the **User** schema is supported — **Groups are not provisioned** (the runner's Group
  lifecycle checks will fail/not apply).
- Required user attributes: `name.familyName`, `name.givenName`, at least one email.
- List returns up to 100 users; `count` max is 100; filter max length 1000 chars.

Sources:
- SCIM v2 API (base URL, endpoints, limits): https://zitadel.com/docs/apis/scim2
- SCIM v2 guide (User-only, required attrs): https://zitadel.com/docs/guides/manage/user/scim2
- Okta SCIM guide (base URL format `${DOMAIN}/scim/v2/{orgId}`, Org User Manager role, PAT/HTTP-Header auth): https://zitadel.com/docs/guides/integrate/scim-okta-guide
- Docker Compose self-hosting: https://zitadel.com/docs/self-hosting/deploy/compose
- Service-account PAT auth: https://zitadel.com/docs/guides/integrate/service-accounts/personal-access-token
- GetMyOrg (orgId lookup): https://zitadel.com/docs/reference/api/management/zitadel.management.v1.ManagementService.GetMyOrg

---

## 4. limosa-io/laravel-scim-server (PHP) — easy new target, verify live

Actively maintained inbound SCIM 2.0 server; it is the backend of the scim.dev SCIM Playground.

```bash
docker run -d -p 8000:8000 --name laravel-scim-server ghcr.io/limosa-io/laravel-scim-server:latest
# or: git clone https://github.com/limosa-io/laravel-scim-server && docker-compose up   # serves on :18123
```

**SCIM base URL:** `http://localhost:8000/scim/v2/` (compose variant: `http://localhost:18123/scim/v2/`);
path configurable via `SCIM_BASE_PATH`.
**Auth:** demo config is open / `auth:sanctum` middleware — verify after startup before filing findings.

Sources: https://github.com/limosa-io/laravel-scim-server , https://scim.dev/opensource/

---

## 5. authentik — inbound SCIM *source* (server) AND outbound *provider* (client)

authentik does both directions:
- **SCIM provider (outbound):** authentik pushes users/groups to a remote SCIM endpoint —
  this is a **client-testable** target for `scim-mockserver`.
  Docs: https://docs.goauthentik.io/add-secure-apps/providers/scim/
- **SCIM source (inbound, since 2024.4; group mappings in 2024.8):** authentik acts as a SCIM
  2.0 **server** that external IdPs provision into — this is **server-testable**.
  Docs: https://docs.goauthentik.io/users-sources/sources/protocols/scim/

Run locally (official compose):

```bash
curl -O https://docs.goauthentik.io/compose.yml
echo "PG_PASS=$(openssl rand -base64 36 | tr -d '\n')" >> .env
echo "AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')" >> .env
docker compose pull && docker compose up -d
# initial setup: http://localhost:9000/if/flow/initial-setup/  (set akadmin password)
```

Create a SCIM **source** in the admin UI; authentik then creates a service account and a
matching **Bearer token**.

**Inbound SCIM base URL:** `http://localhost:9000/source/scim/<source-slug>/v2`
(`/Users`, `/Groups`, `/ServiceProviderConfig`, `/ResourceTypes`).
**Auth:** `Authorization: Bearer <token generated by authentik>`.

> Caveat: the inbound source is documented as provisioning-oriented (list/create/update/delete
> Users and Groups). The docs do **not** confirm `eq` filtering, pagination, or GET-by-id
> semantics that the conformance runner exercises — expect partial results and treat as
> exploratory until confirmed against a running instance.

---

## 6. SCIMple (Apache Directory, ex-Apereo/Penn State) — only via stale image

Real SCIM 2.0 reference impl (Spring Boot example), but Apache ships no official image. The
only ready image is community, ~2 years old, amd64-only:

```bash
docker run -p 8080:8080 --platform linux/amd64 tirasa/scimple-server:latest
```

Base URL / auth not documented on the image page (typically `/v2/`, minimal auth in the
example app) — verify after startup. Building from source (Maven `spring-boot:build-image`)
exceeds the 15-minute bar. Add only if you want a Java/Spring representative and accept the
stale-version caveat.

Sources: https://directory.apache.org/scimple/ , https://github.com/apache/directory-scimple ,
https://hub.docker.com/r/tirasa/scimple-server
