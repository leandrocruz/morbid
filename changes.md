# Morbid

## Unreleased

 - [Leandro] Added new `admin-api` sbt module (ZIO-HTTP + Guara + Endpoint DSL, partner-api style) that proxies CRUD operations to Morbid via `MorbidClient` and gates access to root-account (AccountId 1) users only
 - [Leandro] Added Firebase SSO login flow to the admin frontend; admin-api exchanges Firebase JWT for Morbid session, issues its own `morbid-admin-token` HttpOnly cookie
 - [Leandro] Full CRUD for accounts, users, groups, applications in the admin UI (create/edit/delete + password change, password reset link, PIN set)
 - [Leandro] Shared `morbid.admin.api` DTOs (LoginRequest/Response, AccountResponse, UserResponse, GroupResponse, ApplicationResponse, RoleResponse and create/update bodies) in commons/shared so admin-api (JVM) and admin (JS) share the wire format; zio-schema instances for Endpoint DSL stay in admin-api
 - [Leandro] Added `medulla-firebase` dependency to the admin module and `FirebaseAdmin` config (dev/prod options by host)
 - [Leandro] Added identity-provider lookup to the admin login flow: email is submitted to `POST /login/provider` and the UI then either prompts for a password (`up`) or offers a SAML SSO button (`signInWithPopup(SAMLAuthProvider(id))`); mirrors the presto-console behavior
 - [Leandro] Added shared `LoginMode` enum and `GetProviderRequest`/`GetProviderResponse` DTOs in commons/shared
 - [Leandro] Added filter bar to the Accounts page (name substring, status active/inactive, tenant select populated from loaded accounts) with a clear-filters button and empty-state message
 - [Leandro] Added Docker + deploy scaffolding: `admin-api/build/Dockerfile` + `build-docker-image.sh` (JVM image on `oystr-base-java`), `admin/build/build.sh` (sbt + vite build with optional rsync to host), `admin/build/nginx-site/admin.morbid.{conf,bootstrap.conf}` (letsencrypt-ready nginx site)
 - [Leandro] `docker-compose.yml`: added `morbid-admin-api` service and bind-mounted `/opt/morbid/admin-ui/shared/console/current` into the host nginx as `/var/www/admin-ui` (presto-console pattern: build locally, rsync static files, no separate frontend container)
 - [Leandro] admin-api endpoint paths now follow the ingress-naming convention (routes at `/login`, `/accounts`, ... without `/api/` prefix — nginx strips `/api/` before proxying, matching presto-api)
 - [Leandro] admin-api cookie extraction now parses each `Set-Cookie` response header individually (no more comma-split, which mangled `Expires=Wed, DD Mon ...`)
 - [Leandro] admin-api proxies morbid via a `resolver`-backed variable (`set $upstream ...; proxy_pass $upstream/;`) so nginx reloads don't fail when `morbid-admin-api` isn't running yet
 - [Leandro] RBAC on admin-api: `/me` and the login response now expose `isAdmin` (user has role `adm` on the admin-api's configured application); every mutating endpoint (POST/PUT/DELETE across accounts, users, groups, applications, password/PIN, tenants, providers, api-keys) returns `403 Forbidden` for non-admin callers. Reads remain open to any root-account user.
 - [Leandro] Added Tenants CRUD end-to-end — morbid-server (`FindTenants`/`StoreTenant`/`RemoveTenant` commands + manager routes at `/app/:app/manager/tenants`), admin-api gateway + endpoints + routes, admin UI view (`TenantsView`) with create/edit/delete modals and sidebar entry.
 - [Leandro] Added per-account Identity Providers CRUD end-to-end — morbid-server (`FindProvidersByAccount`/`StoreIdentityProvider`/`RemoveIdentityProvider` commands + routes under `/app/:app/manager/account/:acc/providers`), admin-api gateway + endpoints + routes, admin UI (`ProvidersView`) reachable from a new `Providers` column on the Accounts table; supports both `UP` and `SAML` provider kinds.
 - [Leandro] Added per-account API keys (service accounts) end-to-end — morbid-server routes under `/app/:app/manager/account/:acc/api-keys` that create a `UserKind.SA` user and emit a long-lived token in a single call (reusing `storeUserCommon` + `tokenGiven`), plus listing and revocation; admin-api gateway + endpoints + routes; admin UI (`ApiKeysView`) reachable from a new `API Keys` column on the Accounts table, with a one-time token reveal + copy-to-clipboard modal.
 - [Leandro] Added `DELETE /application/:id` on morbid-server (admin role, requires root account) + matching admin-api endpoint and admin UI delete button on the Applications page.
 - [Leandro] Added shared DTOs in commons/shared: `RawTenantDetails`, `StoreTenantRequest`, `StoreIdentityProviderRequest`, `CreateApiKeyRequest`, `ApiKeyIssued`, plus admin-api wire DTOs (`TenantResponse`, `CreateTenantBody`, `UpdateTenantBody`, `ProviderResponse`, `CreateProviderBody`, `UpdateProviderBody`, `ApiKeyResponse`, `CreateApiKeyBody`, `ApiKeyIssuedResponse`).
 - [Leandro] admin UI: `Session.isAdmin` observable set at login/whoami; every "New X" button and every edit/delete/password/PIN action icon across Accounts, Users, Applications, Groups, Tenants, Providers and API Keys is hidden when the caller lacks the admin role (server-side RBAC still enforces 403 as the source of truth).
 - [Leandro] admin-api no longer has a default application. The admin now picks which application they are working on via a selector in the top bar; every protected admin-api request carries the chosen application via the `X-Admin-App` header, and admin-role gating is evaluated against *that* application (users may be admin on one app but not another). Login/`/me` returns a list of `AppAccess { code, isAdmin }` entries so the UI can render the selector and gate controls per app. The selection is persisted to `localStorage` and auto-selected when the admin has access to exactly one app.
 - [Leandro] admin UI: Roles are now nested under their parent Application (same pattern as Groups). The Applications table gained a `Roles` column linking to a per-app `AppRolesPage`; the standalone Roles sidebar entry was removed. `RolesListView` now takes the application code as a parameter rather than hard-coding `"presto"`.
 - [Leandro] admin UI: refreshed Medulla to the latest `v0.0.1-SNAPSHOT` (publishLocal) so the ScalaJS build picks up the latest Airstream/Laminar helpers.
 - [Leandro] admin UI: added i18n keys (EN + PT) for Tenants, Providers, API Keys and the "API key issued" one-time reveal flow.
 - [Leandro] admin: system-wide Applications listing. New morbid-server command `FindAllApplications` + route `GET /app/:app/manager/applications` (root-only) returns every application regardless of `account_to_app` linkage. admin-api gateway `applications()` now calls the manager endpoint (previously `/applications`, which filtered by caller account and hid apps the root admin had not been linked to). The Admin UI's Applications page now shows every app in the system.
 - [Leandro] admin: the TopBar app selector is now populated from the system-wide application list (not from the token's user.applications, which is account-filtered and only carried `presto` for the root admin). `LoginResponse` is now built asynchronously in admin-api by fetching all applications and deriving `isAdmin` per app from the token's role claims. The selector now shows every application in the system.
 - [Leandro] admin: `/applications` and `/tenants` are system-wide and no longer require the `X-Admin-App` header. admin-api drops the header from these endpoints and gates writes with a new `requireAdminAnywhere` check (needs `adm` on at least one application, instead of a specific one). The admin-UI TopBar hides the app selector on routes where it has no meaning (Applications, Tenants, Dashboard, Login, and any page whose URL already carries an app code — Groups, AppRoles) and keeps it on account-scoped pages.
 - [Leandro] admin: per-app Roles listing is now system-wide. New morbid-server command `FindRolesByApp` + route `GET /app/:app/manager/applications/:code/roles` (root-only) returns every role on that app without the `account_to_app` filter. admin-api gateway `rolesOfApp` now calls the manager endpoint (previously morbid-client's `/app/:app/roles`, which filtered by caller account and hid roles on apps the root admin wasn't linked to). admin-api `/apps/:app/roles` endpoint no longer requires `X-Admin-App` (the path carries the app). Fixes the empty roles page on `oystr360`.
 - [Leandro] admin: per-account app enable/disable. New morbid-server command `UnlinkAccountFromApp` + `FindApplicationsByAccountId`, plus routes under `/app/:app/manager/account/:acc/apps` (list, link by code, unlink by code — all root-only, soft-delete on unlink). admin-api endpoints and gateway methods added. Admin UI gains an `Apps` column on the Accounts table that opens an `AccountAppsPage`: lists every application in the system with a toggle checkbox per row; toggling fires link/unlink on the fly (disabled while in-flight, per-row error reporting). i18n keys (EN + PT) added for the new view.
 - [Leandro] admin: Applications table gained an `Accounts` column (apartment icon + label). Clicking it calls `Session.setSelectedApp(Some(it.code))` and then `AdminRouter.instance.navigateTo(AccountsPage)`, so the TopBar selector lands on that app and the Accounts page opens already filtered to the accounts linked to it. Two bug fixes went with it: (1) `AccountsView` was staying in the Loading state on fresh mount because the Signal→EventBus wiring emitted the initial trigger before `accountsFlow` subscribed (EventBus has no replay) — fixed by subscribing the flow first and using `onMountCallback` + `signal.changes`; (2) the TopBar app selector dropdown was not reflecting a programmatic `Session.setSelectedApp` fired from another page because `child.maybe` was unmounting/remounting the `<select>` on every page change (and a fresh `controlled(value <-- …)` can land on the placeholder before the options are in the DOM) — fixed by creating the selector once as a `val` and toggling `display` on its wrapper so subscriptions stay live for the whole app lifetime.
 - [Leandro] admin: the `/accounts` page now re-fetches whenever the TopBar app selector changes (subscribes to `Session.selectedApp.signal` via an `EventBus` + `flatMapSwitch`). With an app picked, the request carries `X-Admin-App` and admin-api routes to `FindAccountsByApp` (accounts linked to that app). With no app picked, the header is dropped and admin-api routes to a new system-wide listing: morbid-server command `FindAllAccounts` + root-only route `GET /app/:app/manager/accounts/all` (returns every active account across all tenants), fronted by `MorbidGateway.allAccounts()`. So switching the selector filters the table and clearing it shows every account.
 - [Leandro] admin: group-users view. New `GroupUsersPage(acc, app, grp)` at `/accounts/:acc/apps/:app/groups/:grp/users` lists the users in a specific group for a specific (account, app). New morbid-server route `GET /app/:app/manager/account/:acc/apps/:code/groups/:grp/users` (root-only) resolves the account by id and runs `FindUsersInGroup(acc.code, appCode, Some(grpCode))`. admin-api gateway `usersInGroup(app, acc, grp)` + `GET /accounts/:acc/apps/:app/groups/:grp/users` endpoint. Groups table gains a `Users` column (people icon) on each row, linking to the new page with the currently picked app propagated. TopBar hides the app selector on the users-in-group page (the URL already carries both the account and the app).
 - [Leandro] admin: Groups moved from `/applications` to `/accounts` (groups are per-(account, app), not per-app). The Groups column on the Applications page was removed; a new Groups column on the Accounts page links to `AccountGroupsPage(acc)` at `/accounts/:acc/groups`. The Groups page shows an app picker (apps linked to the account, from the existing `/accounts/:acc/apps` endpoint) and auto-selects the first linked app; switching re-fetches. New morbid-server route `GET /app/:app/manager/account/:acc/apps/:code/groups` (root-only) resolves the account by id and runs `FindGroups(acc.code, [appCode])` without the caller's `account_to_app` filter. admin-api gateway `groupsOfApp` now takes `(app, acc)`; admin-api `/apps/:app/groups` accepts an `acc` query param (defaults to the signed-in admin's account) and no longer requires `X-Admin-App` for reads. Create/Delete stay enabled only when viewing the viewer's own account AND they are admin on the picked app (storeGroup/removeGroup still write in the caller's scope). TopBar hides the app selector on the Groups page (the picker is on the page itself). Fixes the 404 "Can't find groups" on `console`/`oystr360` for the root admin.
 - Note on plans: a `Plans` entity does not yet exist in morbid's data model (no `plans` or `features` tables in `repo.scala`), so plan management is deferred until the schema is added — nothing to proxy today.

## Release v1.10.0
LTS: 27/03/2026

 - [Leandro] Added local JWT verification mode to MorbidClient (mode: "local" | "remote")
 - [Leandro] Added JJWT dependencies to morbid-client module
 - [Leandro] MorbidClientConfig now supports key, mode and timezone fields

## Release v1.9.0
LTS: 27/03/2026

 - Added tracking.account
 - Logging some protected requests
 - Using account logging (separate log files for each account)

## Release v1.8.3
LTS: 10/03/2026

- Using guara v1.1.14

## Release v1.8.2
LTS: 09/02/2026

 - Using guara v1.1.13

## Release v1.8.1
LTS: 09/02/2026

- Force the use of lowercase letters in emails (Firebase saves users' emails in lowercase, avoiding case-sensitive discrepancies when the user tries to log in, since the select is case-sensitive).

## Release v1.8.0
LTS: 16/01/2026

 - Using guara v1.1.11
 - The endpoint for provisioning accounts has been added again.

## Release v1.7.1
LTS: 11/12/2025

 - Minor fix at router.scala: When registering a user, if the request is from a non-admin user, it must belong to the same account. 

## Release v1.7.0
LTS: 11/12/2025

 - Added new routes at MorbidClient
 - Enhanced account management system with root account operations:
   - Implemented CRUD operations for accounts
     - `GET /app/{app}/manager/accounts`
     - `POST /app/{app}/manager/account`
     - `DELETE /app/{app}/manager/account/{acc}`
   - Implemented CRUD operations for users
     - `GET /app/{app}/manager/account/{acc}/users`
     - `POST /app/{app}/manager/account/{acc}/user`
     - `DELETE /app/{app}/manager/account/{acc}/user/{id}`

 - Removed the Billing trait
 - Added maxAge configuration to authentication cookies (1 day expiration)

## Release v1.6.0
LTS: 07/10/2025

 - Emitting tokens for service accounts
 - Scala upgrade 3.3.3 -> 3.7.2
 - Configurable days for tokens
 - Added `POST /emit`

## Release v1.5.0
LTS: 05/10/2025

 - Added service token authentication for internal API access
 - New service routes: 
   - `/service/app/{app}/users`
   - `/service/app/{app}/accounts`
 - Added `FindAccountsByApp` and `FindUsersByApp` commands
 - Added `RawAccount` JSON codec support
 - Service configuration with token-based authentication

## Release v1.4.1
LTS: 24/09/2025 

 - Added method to get user from Firebase
 - Fix: When the id is empty, just get the user from Firebase, otherwise try to insert

## Release v1.4.0
LTS: 24/09/2025

 - Temporarily disabled insert users without id in repo
 - Using UID from Firebase

## Release v1.3.0
LTS: 22/09/2025

 - Added ApplicationCode to `MorbidClient.fake(appcode)` (better for testing/mocking)

## Release v1.2.0
LTS: 16/09/2025

 - Improved account/user provisioning
 - Code format
 - Optimizing imports
 - Added script `diff-compare.sc`

## Release v1.1.3
LTS: 11/09/2025

 - Updating firebase-admin from 9.3.0 to 9.6.0
 - Testing the return of auth.generatePasswordResetLink for nulls

## Release v1.1.2
LTS: 09/09/2025

 - Creating new user identities for new users only

## Release v1.1.1
LTS: 09/09/2025

 - Using guara v1.1.9

## Release v1.1.0
LTS: 09/09/2025

 - Returning inactive users

## Release v1.0.0
LTS: 24/07/2025
 
 - Moving the `ImpersonationRequest` to morbid-commons

## Release v0.0.8
LTS: 17/07/2025

 - Added `FakeMorbidClient`

## Release v0.0.7
LTS: 31/03/2025

 - Excluding deleted groups and roles when retrieving users

## Release v0.0.6
LTS: 24/03/2025

 - Using guara v1.1.4

## Release v0.0.5
LTS: 13/03/2025

 - Updating dependencies

## Release v0.0.4
LTS: 12/11/2024

 - Account/User provisioning (temporary)
 - Enabled slf4j logging
 - Added route POST `/app/:app/password/change`
 - Added `MorbidClient.passwordChange`

## Release v0.0.3
LTS: 01/11/2024
 
 - Using chimney 1.3.0
 - Renaming `SingleAppRawUser` to `SingleAppUser`
 - Removing `simple` and `mini`
 - Changed `Token.RawUser` to `Token.CompactUser` for better/smaller serialization
 - Removing dead code
 - Finding users not associated with any groups (refactoring of DatabaseRepo.userGiven)

## Release v0.0.2
LTS: 29/10/2024

 - Added TokenValidator to protected routes
 - Creating legacy users when provisioning SAML users
 - Added MorbidConfig.printQueries
 - Provisioning SAML users
 - Added LegacyMorbid