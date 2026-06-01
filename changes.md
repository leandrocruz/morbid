# Morbid

 - [Leandro] Modelo de Planos e Features por aplicação (suporte ao freemium 2FA do presto)
 - [Leandro] Provisionando contas de usuários
 - [Leandro] Logando erros no `LegacyMorbidImpl`
 - [Leandro] Corrigido conflito de UNIQUE(acc, app, name) em `AccountManager`: `AdminGroupName` agora é `"Admin"` (antes duplicava `"Todos"` com `DefaultGroupName`)

## Release v1.14.0
LTS 20/05/2026

 - [Leandro] Nova rota `POST /app/{app}/user/groups/find` que retorna os grupos a que um usuário pertence (user code vai no corpo via `GetUserGroupsRequest`)
   - Novo `GetUserGroupsRequest(user)` em `morbid-commons`
   - Novo comando de repositório `FindGroupsByUser` com query Quill correspondente
   - Novo método `groupsByUser(request: GetUserGroupsRequest)` no `MorbidClient` (trait, `RemoteMorbidClient`, `LocalMorbidClient` e `FakeMorbidClient`)
 - [Leandro] Nova rota `POST /app/{app}/user/groups` para reatribuir os grupos de um usuário (user code vai no corpo via `SetUserGroupsRequest`; mesma dinâmica de diff add/remove usada em `storeGroup`)
   - Novo `SetUserGroupsRequest(user, groups)` em `morbid-commons`
   - Novo comando de repositório `SetUserGroups` (diffa contra o conjunto atual e insere/deleta linhas em `user_to_group`)
   - Novo método `setUserGroups(request: SetUserGroupsRequest): Task[Boolean]` no `MorbidClient`


## Release v1.13.0
LTS 19/05/2026

 - [Leandro] `POST /impersonate` now stashes the impersonator's JWT in a new `morbid-original-token` HttpOnly cookie
 - [Leandro] `POST /logoff` detects the stash cookie and, when present, restores the impersonator's session (sets `morbid-token` to the stashed JWT, clears the stash) instead of fully logging out
 - [Leandro] `/logoff` now returns `{"restored": Boolean}` so clients can decide whether to reload (restored) or proceed with the normal logout flow
 - [Leandro] `POST /login` now also clears the stash cookie so a fresh login can't inherit a stale impersonator token
 - [Leandro] Added `OriginalToken = "morbid-original-token"` to `MorbidCookies`
 - [Leandro] Added `LogoffResponse(restored: Boolean)` to `morbid-commons` with a `JsonCodec`

## Release v1.12.0
LTS 01/05/2026

 ** Morbid Unification (part 1) **

 - [Leandro] Added `POST /swap` endpoint — exchanges a morbid-legacy token for a morbid token
   - Validates magic password
   - Calls morbid-legacy to resolve the token to a user
   - Issues a new morbid token for the same user (must exist in morbid)
 - [Leandro] Added `userByToken` to `LegacyMorbid` trait
 - [Leandro] Added `client-okhttp` module — Scala 2.12 OkHttp3-based client for Java/Play services
   - Self-contained domain types (no dependency on morbid-commons or ZIO)
   - Supports remote and local (JWT) token verification
 - [Leandro] Added `MorbidHeaders` and `MorbidCookies` constants to `morbid-commons`
 - [Leandro] Replaced raw header/cookie strings with constants in server and client
 - [Leandro] Changed `MagicConfig` to accept multiple passwords (`passwords` list instead of single `password`)
 - [Leandro] Refactored magic validation into `ensureMagic` helper method
 - [Leandro] Added data reconciliation and migration tooling under `data/`

## Release v1.11.1
## Release v1.11.0
LTS: 31/03/2026

 - [Leandro] Removed `ensureResponse` from `appRoute` — callers now handle response wrapping explicitly
 - [Leandro] Added `.toTask` to all `ensureResponse` call sites in morbid-server router
 - [Leandro] Updated guara dependency to v1.2.0

## Release v1.10.1
LTS: 30/03/2026

 - [Matheus] Updating guara-zio `v1.1.14` -> `v1.1.15`

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