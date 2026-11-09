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

## Release v2.11.0
LTS: 03/11/2026

 - [Matheus] Plano `default` explícito no Presto (task #249903): toda conta nova (create e storeAccount) é vinculada ao plano `default`. Migração `sql/migrations/2026-10-23-presto-default-plan.sql` (rodar ANTES do deploy do console e da extensão): cria as features `credentials`, `vault`, `block` e `sign_documents`, monta os planos `default` e `presto_sign` e vincula ao `default` as contas do Presto sem plano base

## Release v2.10.0
LTS: 28/10/2026

 - [Matheus] Ajuste de regex na validação de email, afrouxando validação de propósito (contas migradas do morbid legado causando problemas por causa do regex)

## Release v2.9.2
LTS: 14/10/2026

 - [Leandro] Nova rota de impersonação service-to-service: `POST /service/app/{app}/account/{acc}/impersonate-admin`. Dado o id de uma conta, o servidor elege o admin da conta (o admin ativo mais antigo — eleição determinística, reproduzível para auditoria) e devolve o JWT da sessão impersonada (corpo em texto, como `/swap`). Protegida pelo service token **e** pelo magic, pois diferente de `admins` (apenas leitura) esta rota *emite* uma sessão como admin de qualquer conta. Adicionado o método correspondente `impersonateAccountAdmin(account, magic)(using ServiceToken, ApplicationCode): Task[RawToken]` no `MorbidClient` (`Remote`/`Local`/`Fake`) e o DTO `ImpersonateAccountAdminRequest` em commons. Usado pelo partner-api para autenticar no presto-api (listagem de 2FA) sem precisar descobrir o email do admin nem lidar com o cookie de `/impersonate`
 - [Leandro] Correção no `RemoteMorbidClient`: o helper `delete[T]` enviava `Request.get` em vez de `Request.delete`, fazendo com que `managerRemoveAccount` e `managerRemoveUser` chamassem o servidor com o método errado (nenhuma rota GET correspondente → 404). Encontrado durante os testes do partner-api
 - [Leandro] Falhas de corrida em `/provision` por identificador ou email já existentes (violação de unicidade durante a transação, após os prechecks) voltam a retornar 409 em vez do erro genérico "Error provisioning account" — restaura o comportamento documentado na v2.5.0, que havia regredido: o `mapError` genérico do router engolia `IdentifierTakenException`/`EmailTakenException`. `errors.scala` ganhou as variantes `emailTakenError`/`identifierTakenError` (valores) e os helpers de efeito passaram a delegar para elas — mensagem, código e status definidos em um único lugar

## Release v2.9.1
LTS: 06/10/2026

 - [Junior] `usersByAccount` (rota `GET /app/{app}/manager/account/{acc}/users`) passa a retornar todos os usuários da conta, inclusive inativos e removidos, e também de contas inativas ou removidas, para exibição no console do Presto

## Release v2.9.0
LTS: 27/08/2026

 - [Leandro] `RemoteMorbidClient.exec` não converte mais falhas UEF em erro genérico 500: o `ReturnUnifiedError` vindo do servidor (ex: 403 "Error verifying token" para token expirado) agora é propagado com o status original, permitindo que os consumidores (ex: presto-api → console) tratem 401/403 corretamente (logout)
 - [Leandro] `LocalMorbidClient.tokenFrom` agora falha com `ReturnUnifiedError` 403 ("Error verifying token", code `MorbidError.Forbidden`) para token expirado/inválido, espelhando o comportamento do servidor — antes a exceção genérica virava 500 no guara

## Release v2.8.2
LTS: 24/08/2026

 - [Matheus] Ajuste no método `admins` do client (rota errada)

## Release v2.8.1
LTS: 21/08/2026

 - [Matheus] Removendo captura de Morbid-Token em rotas de service, mantendo apenas o ServiceToken
 - [Matheus] Ajuste no client da rota admins para passar opcionalmente uma conta, passando uma conta, será feito a busca dos admins daquela conta, se omitido, será feito a busca de todos os admins de um app

## Release v2.8.0
LTS: 20/08/2026

 - [Matheus] Add endpoint to get admin users by accounts
   - `GET /service/app/{app}/accounts/admins`
 - [Matheus] Implementation to call service routes for MorbidClient (client.scala)

## Release v2.7.0
LTS: 20/08/2026

 - [Leandro] Logando `UserRow.active` e `UserRow.deleted` na atualização dos usuários (mascarenhas)
 - [Leandro] Nova coluna `UserRow.updated`
 - [Leandro] Parsing UEF error at `RemoteMorbidClient.perform`

## Release v2.6.0
LTS: 17/07/2026

 - [Leandro] Opções customizadas para o cliente http do Morbid

## Release v2.5.0
LTS: 10/07/2026

 - [Leandro] Nova rota `POST /account/by-identifier` (protegida por `magic`) que retorna `Option[RawAccount]` (JSON `null` quando não encontrado). Novo `FindAccountByIdentifierRequest(magic, identifier)` em `morbid-commons`, comando `FindAccountByIdentifier` no servidor com query Quill correspondente, e método `accountByIdentifier(request)` no `MorbidClient` (trait, `RemoteMorbidClient`, `LocalMorbidClient` e `FakeMorbidClient`)
 - [Leandro] Nova coluna `accounts.identifier` (nullable, `VARCHAR(256)`) para armazenar CPF/CNPJ da conta. Índice único parcial `accounts_identifier_key ON accounts (identifier) WHERE identifier IS NOT NULL` — duas contas só podem compartilhar `identifier` se ambos forem `NULL`. Removida a constraint `UNIQUE(tenant, name)`: o nome da conta volta a ser apenas rótulo de exibição; a chave de negócio passa a ser `identifier`. Script idempotente em `sql/migrations/2026-06-19-add-account-identifier.sql` (`ADD COLUMN IF NOT EXISTS` + `DROP CONSTRAINT IF EXISTS` + `CREATE UNIQUE INDEX IF NOT EXISTS`, dentro de `BEGIN/COMMIT`)
 - [Leandro] Novo `opaque type AccountIdentifier = String` em `morbid.types` (companion `OpaqueOps`, `JsonEncoder`/`JsonDecoder`, `MappedEncoding` para Quill). Propagado para `RawAccount`, `ProvisionRequest`, `StoreAccountRequest`, `CreateAccount`, `StoreAccount` (command interno) e `AccountRow`
 - [Leandro] `LegacyMorbid.accountByIdentifier(identifier)` — novo método cliente que consulta `GET /account/identifier/:it` no legacy-morbid e retorna `Option[LegacyAccount]` (404 → `None`, 200 → `Some(...)`, demais códigos viram exceção). Mesmo padrão de `accountById`
 - [Leandro] `CreateLegacyAccountRequest` e `LegacyAccount` ganham `identifier: Option[AccountIdentifier]`. O fluxo `accounts.provision` agora propaga `request.identifier` para o legacy-morbid backend (que também passou a aceitar/armazenar o campo — vide changes.md do morbid-deprecated). Isso permite que o legacy-morbid use o `identifier` como chave única no lugar do nome — então duas contas com mesmo nome de exibição mas CPF/CNPJ distintos não colidem mais
 - [Leandro] `/provision` faz pre-check explícito de `identifier` via `FindAccountByIdentifier` (helper `ensureIdentifierAvailable`) antes de chamar `accounts.provision`. Erro retornado imediatamente como `409 Conflict` sem tocar Firebase/legacy-morbid. O índice único parcial `accounts_identifier_key` continua como rede de segurança contra race condition entre duas requisições simultâneas
 - [Leandro] `/provision` agora responde `409 Conflict` (em vez de `500` com mensagem genérica) quando o `identifier` ou o `email` já estão em uso. Erros tipados `IdentifierTakenException` e `EmailTakenException` (em `morbid.accounts`) substituem o `Exception` genérico que antes engolia a causa específica — o router pattern-matcha e devolve `{"message":"Identifier 'X' already exists"}` ou `{"message":"Email 'X' already exists"}` com status 409, demais erros continuam como 500
 - [Leandro] `accounts.provision` propaga `identifier` do `ProvisionRequest` para o `StoreAccount`. Helper de tradução de erro `asNameTaken` renomeado para `asIdentifierTaken` (agora casa a violação `accounts_identifier_key`)
 - [Leandro] `/provision` agora exige `magic` no `ProvisionRequest` e valida via `ensureMagic` antes de qualquer side-effect (Firebase, legacy-morbid). Protege o endpoint público de abuso/spam que consumia quota de identidade e criava contas órfãs
 - [Leandro] Melhorando a regexp de validação de emails
 - [Leandro] Removendo `ProvisionNameTaken`, `ProvisionEmailTaken`, `ProvisionBadIntent` e `UnknownUser`
 - [Leandro] Adicionando `MorbidClient.provisionRaw`

## Release v2.4.0
LTS 03/07/2026

 - [Leandro] Adicionando `CloudUser` como abstração extra não referenciar diretamente o `UserRecord`
 - [Leandro] Adicionando implementações de teste para `Identities` e `TokenGenerator`
 - [Leandro] Refatorando a criação dos grupos ao criar uma conta

## Release v2.3.1
LTS 02/07/2026

 - [Leandro] Associando o grupo admin com a permissão `adm` (role id = 1)

## Release v2.3.0
LTS 01/07/2026

 - [Leandro] Refactoring da criação de contas (endpoint POST `/app/$app/account`)

## Release v2.2.1
LTS 18/06/2026

 - [Matheus] Updated guara dependency to v1.3.1

## Release v2.2.0
LTS 16/06/2026

 - [Leandro] `AccountName` aumentado de 64 para 256 caracteres (decoder `safeLatinName` em `commons.scala` e coluna `accounts.name` em `sql/schema.sql`)

## Release v2.1.0
LTS 15/06/2026

 - [Leandro] `MorbidClient.exec` agora lê o corpo da resposta em erros não-200 e inclui no `Exception`, expondo o `CommonError` (com `trace`) do servidor em vez de um `ReturnResponseError` sem mensagem

## Release v2.0.0
LTS 01/06/2026

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