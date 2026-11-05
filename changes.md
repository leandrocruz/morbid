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