# Morbid Unification — Migration Plan

**Goal:** Deprecate and remove `morbid-deprecated` (ml), making `morbid` (m) the single authentication service across all projects.

**Date:** 2026-04-22

---

## Current State

### Two Authentication Services

| Aspect                | morbid-deprecated (ml)                          | morbid (m)                                              |
|-----------------------|-------------------------------------------------|---------------------------------------------------------|
| **Used by**           | oystr/ projects                                 | oystr/presto/ projects, guara-app-skeleton, edge-gateway |
| **Framework**         | Play/Akka                                       | ZIO                                                     |
| **Token payload**     | Standard JWT Claims, `subject` = password token | Full JSON Token (user, applications, groups, roles)     |
| **JWT headers**       | Standard (`alg`, `typ`)                         | Custom (`version`, `issuer`, `contentType`)             |
| **Signing**           | HS512, Base64-encoded key                       | HS512, Base64-encoded key (same algorithm)              |
| **Client library**    | `client-okhttp` (OkHttp3)                       | `morbid-client` (ZIO)                                  |
| **Database**          | 4 tables (flat)                                 | 12 tables (multi-tenant RBAC)                           |
| **Auth model**        | user -> permissions (direct)                    | user -> group -> role -> permission                     |
| **Password storage**  | `secrets` table                                 | Firebase/Google Cloud Identity                          |
| **Cross-compatible?** | NO                                              | NO                                                      |

### Token Forwarding Chain

The ml token does **not** stay isolated per service. Edge services extract it, derive headers, and forward both downstream:

```
Browser -> [oystr-vi cookie / X-Oystr-Auth header]
  -> plexus / api-gateway / rest-api (AuthFilter)
     -> validates ml token against cached user list
     -> injects X-Oystr-AccountId, X-Oystr-UserId headers
     -> forwards original token as Authorization header
       -> execution-service (trusts upstream, does NOT validate)
         -> forwards X-Oystr-Auth to api-gateway for single executions
         -> forwards X-Oystr-AccountId to bot-service
         -> passes account/user to vault
       -> bot-service -> bot-wrapper -> bots (headers flow through)
       -> vault-legacy / vault-proxy (Authorization header forwarded)
       -> api-controller (receives account/user/token)
```

### Database Coupling

Vault queries `accounts` and `users` tables **directly from the morbid database** (shared DB, not replication). Vault's Quill mappings expect specific columns from those tables.

### Consumer Inventory

#### Edge services (validate ml tokens, derive headers, forward downstream)

| Service               | Integration                                    | Notes                                                      |
|-----------------------|------------------------------------------------|------------------------------------------------------------|
| `rest-api`            | AuthFilter + UserCache actor + login + password | Most complex. Calls ml for login, token validation, cache. |
| `plexus`              | JWT validation + user cache + header enrichment | Adds X-Oystr-AccountId, X-Oystr-UserId, Authorization.    |
| `api-gateway`         | JWT validation + user cache + proxy             | Forwards all headers to controller service.                |

#### Direct HTTP callers (call ml API directly)

| Service                  | Endpoints called                                         |
|--------------------------|----------------------------------------------------------|
| `cpj-connector`          | POST /user/login                                         |
| `legalone-connector`     | POST /user/login, GET /user/token, GET /user/id, POST /user/impersonate |
| `control-panel-service`  | POST /user, POST /user/impersonate, POST /user/password/change |
| `vault-legacy`           | GET /user/token/{jwt} (HTTP validation)                  |

#### Shared database readers

| Service   | Tables read                        | Notes                              |
|-----------|------------------------------------|------------------------------------|
| `vault`   | `accounts`, `users` (Quill direct) | Expects `parent_id`, `name`, etc.  |

#### Type/library consumers (dependency only)

| Service              | Dependency                                   |
|----------------------|----------------------------------------------|
| `edge-gateway`       | `morbid-commons` types (AccountId, UserId)   |
| `guara-app-skeleton` | `morbid-client` (new m, ZIO)                 |
| `presto-shared`      | `morbid-client` v1.11.1 (new m, ZIO)        |
| `presto-api`         | via presto-shared                            |
| `event-router`       | `morbid-client` v1.10.0 (new m, ZIO)        |
| `presto-handlers`    | `morbid-client` v1.7.0 (new m, ZIO)         |
| `pdf-signer`         | `morbid-client` v0.0.8 (new m, ZIO)         |

### Schema Comparison (from Slick/Quill mappings)

**ml (Slick)** — 4 tables:

- `accounts`: id, created, deleted, active, name, type
- `users`: id, account (FK), created, deleted, active, name, email, type
- `secrets`: id, user_id (FK), created, deleted, method, password, token
- `permissions`: id, user_id (FK), created, deleted, name

**m (Quill)** — 12 tables:

- `tenants`: id, created, deleted, active, code, name
- `accounts`: id, created, deleted, tenant (FK), active, code, name
- `users`: id, created, deleted, account (FK), kind, code, active, email
- `pins`: id, created, deleted, user_id (FK), pin
- `applications`: id, created, deleted, active, code, name
- `identity_providers`: id, created, deleted, account (FK), active, domain, kind, code, name
- `groups`: id, created, deleted, app (FK), acc (FK), code, name
- `roles`: id, created, deleted, app (FK), code, name
- `permissions`: id, created, deleted, rid (FK), code, name
- `account_to_app`: acc (FK), app (FK), created, deleted
- `user_to_group`: usr (FK), app (FK), grp (FK), created, deleted
- `group_to_role`: grp (FK), rid (FK), created, deleted

**Vault's expected shape** (Quill mappings for morbid tables):

- `accounts`: id, parent_id, created, deleted
- `users`: id, created, active, deleted, name, email

---

## Constraints

| # | Constraint                    | Impact                                                                                   |
|---|-------------------------------|------------------------------------------------------------------------------------------|
| 1 | Token chain                   | ml tokens flow edge-to-deep. Migration must handle the full request path.                |
| 2 | Database divergence            | ml and m have fundamentally different schemas. Data may not be in sync.                  |
| 3 | No OkHttp3 client for m       | Play/Akka services cannot use the ZIO-based morbid-client.                               |
| 4 | Vault shared DB               | Vault queries accounts/users directly. Schema change breaks vault.                       |
| 5 | Derived headers               | Edge services produce X-Oystr-AccountId + X-Oystr-UserId. IDs must match across systems. |

---

## Migration Phases

### Phase 0 — Data Reconciliation

**Goal:** Ensure m's database has all users and accounts from ml, with matching IDs.

**Steps:**

1. Audit both databases — extract all accounts and users from ml and m, compare IDs, emails, active status.
2. Build a sync tool (one-time migration script) that:
   - Creates a default tenant in m for existing ml data.
   - Imports ml `accounts` into m's `accounts` table, preserving IDs.
   - Imports ml `users` into m's `users` table, preserving IDs.
   - Maps ml `permissions` to m's groups/roles (or creates a "legacy" group with equivalent roles).
   - Handles password/secret migration (see open question #1).
3. Validate — run the sync, compare counts, spot-check critical users.
4. Decide on ongoing sync — until full cutover, determine if ml and m need to stay in sync (periodic sync job or dual-write via m's legacy module).

**Acceptance criteria:**
- Every ml user/account exists in m with the same numeric ID.
- A token issued by m for any migrated user contains correct authorization data.

---

### Phase 1 — Build OkHttp3 morbid-client for m

**Goal:** Give Play/Akka services a drop-in client to talk to m.

**Steps:**

1. Create a new module `client-okhttp` in the morbid project.
2. Design the client API to mirror ml's `client-okhttp` interface where possible:
   - `authenticateUser(email, password)` -> calls m's `POST /login`
   - `byToken(token)` -> calls m's `POST /verify`
   - `byId(id)` -> calls m's user lookup
   - `byEmail(email)` -> calls m's user lookup
   - `bulkUsers(...)` -> calls m's `/service/app/{app}/users` or new equivalent
   - `createUser(...)`, `resetPassword(...)`, `changePassword(...)`, `impersonate(...)`
3. Handle API shape differences — the client translates between ml-style requests and m's app-scoped endpoints.
4. Publish as a Maven artifact.

**Acceptance criteria:**
- Play/Akka services can depend on the new client without pulling in ZIO.
- All ml client-okhttp methods have equivalents in the new client.
- Integration tests pass against a running m instance.

---

### Phase 2 — Migrate Edge Services

**Goal:** Move token issuance and validation from ml to m at the edge.

**Strategy:** Since downstream services consume derived headers (`X-Oystr-AccountId`, `X-Oystr-UserId`), they are transparent to which auth system produced those headers — as long as IDs match (ensured by Phase 0).

**For each edge service:**

1. Replace ml client/HTTP calls with the new OkHttp3 morbid-client.
2. Update JWT validation to handle m's token format (or use m's `/verify` endpoint).
3. Update user cache sync to pull from m instead of ml.
4. Update login flow to authenticate against m.
5. Keep producing the same derived headers (`X-Oystr-AccountId`, `X-Oystr-UserId`, `Authorization`).
6. Update cookies (`oystr-vi`) to contain m tokens instead of ml tokens.

**Migration order:**

1. **api-gateway** — simplest proxy logic, good canary.
2. **plexus** — similar pattern, adds enriched headers.
3. **rest-api** — most complex (AuthFilter + UserCache + login + password flows), migrate last.

**Rollback:** Config toggle to switch between ml and m per edge service. If m fails, revert to ml without redeployment.

**Acceptance criteria:**
- Edge service authenticates against m, issues m tokens.
- Downstream services continue to function with no changes (same derived headers, same ID values).
- Login, logout, password reset, impersonation all work through m.

---

### Phase 3 — Migrate Vault's Shared Database Access

**Goal:** Point vault at m's database tables instead of ml's.

**Problem:** Vault's Quill mappings expect a specific column shape for `accounts` and `users` that differs from m's schema.

| Vault expects       | ml has | m has                |
|---------------------|--------|----------------------|
| `accounts.id`       | yes    | yes                  |
| `accounts.parent_id`| no     | no (has `tenant`)    |
| `users.id`          | yes    | yes                  |
| `users.name`        | yes    | no (has `code`)      |
| `users.email`       | yes    | yes                  |
| `users.active`      | yes    | yes                  |

**Options:**

- **A. Create database views** in m's database that expose `accounts` and `users` in the shape vault expects. Least invasive.
- **B. Update vault's Quill mappings** to match m's schema. More work but cleaner long-term.
- **C. Both** — views for immediate compatibility, then migrate vault code.

**Recommended:** Option C. Deploy views first for zero-downtime cutover, then update vault code at leisure.

**Acceptance criteria:**
- Vault reads accounts and users from m's database (directly or via views).
- All vault operations (secret storage, retrieval, history) work with m's data.
- No data loss or access errors during cutover.

---

### Phase 4 — Migrate Remaining Direct-Call Services

**Goal:** Replace ml HTTP calls in services that are not in the main token chain.

These are independent and can be migrated in parallel:

| Service                  | Work required                                                |
|--------------------------|--------------------------------------------------------------|
| `cpj-connector`          | Replace POST /user/login call with new OkHttp3 client.      |
| `legalone-connector`     | Replace login + token validation + impersonation calls.      |
| `control-panel-service`  | Replace user management + impersonation calls.               |
| `vault-legacy`           | Replace GET /user/token HTTP validation with new client.     |
| `edge-gateway`           | Change dependency from `morbid-commons` (ml) to m's commons.|

**Acceptance criteria:**
- Each service authenticates and manages users via m.
- No remaining references to ml endpoints or ml client library.

---

### Phase 5 — Decommission ml

**Goal:** Remove all traces of ml.

**Steps:**

1. Remove m's `legacy` module (no longer needed for ID bridging).
2. Shut down the ml service.
3. Back up and drop the ml database.
4. Remove database views from Phase 3 (if vault code was updated in Phase 3C).
5. Remove any sync jobs from Phase 0.
6. Remove ml dependency declarations from all build files.
7. Archive the morbid-deprecated repository.

**Acceptance criteria:**
- No running service depends on ml.
- No build file references ml artifacts.
- ml service and database are offline.

---

## Risk Mitigation

| Risk                               | Mitigation                                                                   |
|------------------------------------|------------------------------------------------------------------------------|
| ID mismatch between ml and m       | Phase 0 sync with ID preservation + validation.                             |
| Edge service rollback needed       | Config toggle to switch between ml/m per edge service.                      |
| Vault breaks on schema change      | Database views (Phase 3A) provide backward compatibility.                   |
| Bulk user cache endpoint missing   | Add equivalent endpoint to m before Phase 2, or adapt `/service/app/{app}/users`. |
| Password migration                 | Depends on open question #1. May need m to support direct email/password.   |
| Downstream service validates raw token | Identify all such services in Phase 2 prep. Update them alongside edge migration. |

---

## Open Questions

1. **Password auth:** Does m support direct email/password login, or only Firebase? If only Firebase, how do existing ml users transition their passwords?
2. **Bulk user endpoint:** Does m have an equivalent to ml's `GET /users` with `X-Morbid-Magic`? If not, we need to add one before Phase 2.
3. **`accounts.parent_id`** in vault's Quill mapping — is this column used in production? It does not exist in either ml or m schema.
4. **Downstream token validation:** Which services beyond the edge actually decode/validate the raw `Authorization` token (vs. just trusting derived headers)?
5. **Deprecation candidates:** Can any services be retired entirely rather than migrated (e.g., vault-legacy, cpj-connector)?
6. **Ongoing sync:** During the migration window (Phase 0 through Phase 5), do we need bidirectional sync between ml and m databases, or is one-time import sufficient?

---

## API Endpoint Mapping: ml -> m

For reference when building the OkHttp3 client (Phase 1):

| ml endpoint                      | Method | m equivalent                               | Status  | Notes                                    |
|----------------------------------|--------|--------------------------------------------|---------|------------------------------------------|
| `/user/login`                    | POST   | `POST /login`                              | EQUIVALENT | Different request shape. m uses Firebase verification. |
| `/user/token/{token}`            | GET    | `POST /verify`                             | EQUIVALENT | ml: GET path param. m: POST body.        |
| `/user/id/{id}`                  | GET    | `GET /user?id={id}`                        | EQUIVALENT | m uses query param.                      |
| `/user/email/{email}`            | GET    | `GET /user?email={email}`                  | EQUIVALENT | m uses query param.                      |
| `/users` (bulk, X-Morbid-Magic) | GET    | `GET /service/app/{app}/users`             | PARTIAL | m requires service token + app context.  |
| `/user` (create)                 | POST   | `POST /app/{app}/user`                     | EQUIVALENT | Different request shape. m is app-scoped.|
| `/user` (update)                 | PUT    | `POST /app/{app}/user` (update=true)       | EQUIVALENT | m uses same endpoint with flag.          |
| `/user/password/reset`           | POST   | `POST /app/{app}/password/reset`           | EQUIVALENT | m returns link, not user.                |
| `/user/password/change`          | POST   | `POST /app/{app}/password/change`          | EQUIVALENT | Different request shape.                 |
| `/user/password/force`           | POST   | —                                          | MISSING | No m equivalent.                         |
| `/user/impersonate`              | POST   | `POST /impersonate`                        | EQUIVALENT | ml uses `master`, m uses `magic`.        |
| `/user/refresh`                  | POST   | —                                          | MISSING | No m equivalent.                         |
| `/user/permission/assign`        | POST   | —                                          | MISSING | m uses groups/roles instead.             |
| `/account` (create)              | POST   | `POST /app/{app}/account`                  | EQUIVALENT | m requires auth + app context.           |
| `/account/id/{id}`               | GET    | —                                          | PARTIAL | m has manager API only.                  |
| `/account/{id}/users`            | GET    | `GET /app/{app}/manager/account/{acc}/users`| EQUIVALENT | m requires manager role.                |
| `/account/{a}/user/{u}` (delete) | DELETE | `DELETE /app/{app}/manager/account/{acc}/user/{code}` | EQUIVALENT | m uses code, not numeric ID.    |
