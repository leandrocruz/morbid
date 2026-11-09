package morbid.admin.api

import ApiError.{api, badInput, forbidden, notFound}
import guara.router.Router
import guara.uef
import morbid.admin.api.codecs.given
import morbid.domain.raw.*
import morbid.domain.requests.*
import morbid.domain.token.RawToken
import morbid.types.*
import zio.*
import zio.http.*

import scala.util.Try

case class AdminRouter(auth: AdminAuth, gw: MorbidGateway, cfg: AppConfig) extends Router {

  private def session(header: Option[AuthorizationHeader], cookies: Option[String]): IO[ApiError, AdminSession] = {
    val raw = cookies.flatMap(extractCookie(cfg.cookie.name))
    auth.authenticate(header, raw)
  }

  /** Parses the mandatory `X-Admin-App` header: the application the admin is
    * working on. All protected routes carry it; missing header is a 400. */
  private def parseAdminApp(header: Option[String]): IO[ApiError, ApplicationCode] =
    header.map(_.trim).filter(_.nonEmpty) match {
      case Some(code) => ZIO.succeed(ApplicationCode.of(code))
      case None       => ZIO.fail(badInput("Missing 'X-Admin-App' header: select an application"))
    }

  /** Read session gated by app context. `app` only scopes the morbid URL; no admin check. */
  private def readSession(header: Option[AuthorizationHeader], cookies: Option[String], adminApp: Option[String]): IO[ApiError, (AdminSession, ApplicationCode)] =
    for
      s   <- session(header, cookies)
      app <- parseAdminApp(adminApp)
    yield (s, app)

  /** Write session gated by app context: requires the admin role on the selected app. */
  private def writeSession(header: Option[AuthorizationHeader], cookies: Option[String], adminApp: Option[String]): IO[ApiError, (AdminSession, ApplicationCode)] =
    for
      pair <- readSession(header, cookies, adminApp)
      (s, app) = pair
      _    <- auth.requireAdmin(s, app)
    yield (s, app)

  private def extractCookie(name: String)(header: String): Option[String] =
    header.split(";").iterator
      .map(_.trim)
      .collectFirst { case s if s.startsWith(s"$name=") => s.drop(name.length + 1) }
      .filter(_.nonEmpty)

  private def parseAccountId(raw: String): IO[ApiError, AccountId] =
    ZIO.fromTry(Try(AccountId.of(raw.toLong))).mapError(_ => badInput(s"Invalid account id '$raw'"))

  private def parseUserCode(raw: String): IO[ApiError, UserCode] =
    ZIO.succeed(UserCode.of(raw))

  private def parseGroupCode(raw: String): IO[ApiError, GroupCode] =
    ZIO.succeed(GroupCode.of(raw))

  private def parseAppCode(raw: String): IO[ApiError, ApplicationCode] =
    ZIO.succeed(ApplicationCode.of(raw))

  private def toAccount(acc: RawAccount): AccountResponse =
    AccountResponse(acc.id, acc.code, acc.name, acc.tenant, acc.active, acc.created)

  private def toUser(u: RawUserEntry): UserResponse =
    UserResponse(u.id, u.code, u.email, u.active, u.kind, u.account, u.created)

  private def toGroup(g: RawGroup): GroupResponse =
    GroupResponse(g.id, g.code, g.name, g.roles.map(_.code).toList)

  private def toApp(a: RawApplicationDetails): ApplicationResponse =
    ApplicationResponse(a.id, a.code, a.name, a.active, a.created)

  private def toRole(r: RawRole): RoleResponse =
    RoleResponse(r.id, r.code, r.name)

  /** Build the LoginResponse — the app list drives the TopBar selector, so it
    * must be system-wide, not scoped to the admin's account. We fetch all
    * applications from morbid-server and derive `isAdmin` per app from the
    * token's own role claims (an admin only has `adm` on apps that were
    * granted to them; the extra apps in the selector just let the admin
    * navigate, with CRUD gated per app by RBAC). */
  private def toLoginResponse(session: AdminSession): IO[ApiError, LoginResponse] = {
    given RawToken = session.raw
    gw.applications().api.map { all =>
      val apps = all.map(a => AppAccess(code = a.code, isAdmin = session.isAdminOn(a.code))).toList
      LoginResponse(session.email, session.account, None, apps)
    }
  }

  /* auth */

  private def errorResponse(err: ApiError): Response = {
    val status = Status.fromInt(err.uef.status)
    Response(status = status, body = Body.fromString(zio.json.EncoderOps(err.uef).toJson))
      .addHeader(uef.UEFHeader)
  }

  private val loginWithCookie: Routes[Any, Nothing] = Routes(
    Method.POST / "login" -> Handler.fromFunctionZIO[Request] { request =>
      val handle: ZIO[Any, Response, Response] = for
        raw      <- request.body.asString.mapError(e => errorResponse(badInput(s"Could not read body: ${e.getMessage}")))
        body     <- ZIO.fromEither(zio.json.JsonDecoder[LoginRequest].decodeJson(raw))
                      .mapError(err => errorResponse(badInput(err)))
        pair     <- auth.login(body.firebaseToken).mapError(errorResponse)
        (session, cookie) = pair
        response <- toLoginResponse(session).mapError(errorResponse)
      yield Response.json(zio.json.EncoderOps(response).toJson).addCookie(cookie)
      handle.merge
    }
  ).sandbox

  private val logoffRoute: Routes[Any, Nothing] = Routes(
    Method.POST / "logoff" -> Handler.fromFunctionZIO[Request] { request =>
      val resp     = Response.json("true").addCookie(auth.logoutCookie)
      val maybeRaw = request.cookies.collectFirst { case c if c.name == cfg.cookie.name => c.content }
      maybeRaw.map(RawToken.of) match
        case Some(rawToken) => gw.logoff(rawToken).ignore.as(resp)
        case None           => ZIO.succeed(resp)
    }
  ).sandbox

  private val loginProviderRoute = endpoints.loginProvider.implement { req =>
    gw.loginProvider(req.email).api
  }

  private val whoamiRoute = endpoints.whoami.implement { case (cookies, header) =>
    for
      s   <- session(header, cookies)
      out <- toLoginResponse(s)
    yield out
  }

  /* accounts */

  /** List accounts. With `X-Admin-App`, the server-side manager route filters
    * by `account_to_app` on that app; without it, the route returns every
    * account in the system (root-only). Admin UI drops the header when no app
    * is picked in the TopBar. */
  private val listAccountsRoute = endpoints.listAccounts.implement { case (cookies, header, adminApp) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      items <- adminApp.map(_.trim).filter(_.nonEmpty) match
                 case Some(code) =>
                   given ApplicationCode = ApplicationCode.of(code)
                   gw.accounts().api
                 case None =>
                   gw.allAccounts().api
    yield items.map(toAccount).toList
  }

  private val createAccountRoute = endpoints.createAccount.implement { case (cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      req       = StoreAccountRequest(id = None, tenant = body.tenant, name = body.name, code = body.code, active = body.active, update = false)
      acc      <- gw.storeAccount(req).api
    yield toAccount(acc)
  }

  private val updateAccountRoute = endpoints.updateAccount.implement { case (acc, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      existing <- gw.accounts().api.map(_.find(_.id == id)).someOrFail(notFound(s"Account '$acc' not found"))
      req       = StoreAccountRequest(id = Some(id), tenant = existing.tenant, name = body.name, code = existing.code, active = body.active, update = true)
      updated  <- gw.storeAccount(req).api
    yield toAccount(updated)
  }

  private val deleteAccountRoute = endpoints.deleteAccount.implement { case (acc, cookies, header, adminApp) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      _        <- gw.removeAccount(id).api
    yield true
  }

  /* users */

  private val listUsersRoute = endpoints.listUsers.implement { case (acc, cookies, header, adminApp) =>
    for
      pair     <- readSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      items    <- gw.usersOfAccount(id).api
    yield items.map(toUser).toList
  }

  private val createUserRoute = endpoints.createUser.implement { case (acc, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      req       = StoreUserRequest(id = None, code = None, kind = body.kind, email = body.email, password = None, tenant = None, active = body.active, update = false)
      user     <- gw.storeUserFor(id, req).api
    yield toUser(user)
  }

  private val updateUserRoute = endpoints.updateUser.implement { case (acc, usr, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      code     <- parseUserCode(usr)
      current  <- gw.usersOfAccount(id).api.map(_.find(_.code == code)).someOrFail(notFound(s"User '$usr' not found"))
      req       = StoreUserRequest(id = Some(current.id), code = Some(current.code), kind = current.kind, email = body.email, password = None, tenant = None, active = body.active, update = true)
      updated  <- gw.storeUserFor(id, req).api
    yield toUser(updated)
  }

  private val deleteUserRoute = endpoints.deleteUser.implement { case (acc, usr, cookies, header, adminApp) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      code     <- parseUserCode(usr)
      _        <- gw.removeUserFrom(id, code).api
    yield true
  }

  private val changePasswordRoute = endpoints.changePassword.implement { case (cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      _        <- gw.passwordChange(ChangePasswordRequest(body.email, body.password)).api
    yield true
  }

  private val resetPasswordRoute = endpoints.resetPassword.implement { case (cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      link     <- gw.passwordResetLink(RequestPasswordRequestLink(body.email)).api
    yield PasswordResetResponse(link.link)
  }

  private val setPinRoute = endpoints.setPin.implement { case (cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      _        <- gw.setPin(SetUserPin(body.email, body.pin)).api
    yield true
  }

  /* groups */

  private val listGroupsRoute = endpoints.listGroups.implement { case (appParam, cookies, header, accQ) =>
    for
      s       <- session(header, cookies)
      given RawToken = s.raw
      code    <- parseAppCode(appParam)
      acc      = accQ.map(AccountId.of).getOrElse(s.account)
      items   <- gw.groupsOfApp(code, acc).api
    yield items.map(toGroup).toList
  }

  private val createGroupRoute = endpoints.createGroup.implement { case (appParam, cookies, header, adminApp, body) =>
    for
      pair    <- writeSession(header, cookies, adminApp)
      (s, _)   = pair
      given RawToken = s.raw
      code    <- parseAppCode(appParam)
      req      = StoreGroupRequest(id = None, code = body.code, name = body.name, users = body.users, roles = body.roles)
      group   <- gw.storeGroup(code, req).api
    yield toGroup(group)
  }

  private val deleteGroupRoute = endpoints.deleteGroup.implement { case (appParam, grp, cookies, header, adminApp) =>
    for
      pair    <- writeSession(header, cookies, adminApp)
      (s, _)   = pair
      given RawToken = s.raw
      code    <- parseAppCode(appParam)
      gcode   <- parseGroupCode(grp)
      _       <- gw.removeGroup(code, RemoveGroupRequest(gcode)).api
    yield true
  }

  private val listGroupUsersRoute = endpoints.listGroupUsers.implement { case (accParam, appParam, grpParam, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      acc   <- parseAccountId(accParam)
      code  <- parseAppCode(appParam)
      gcode <- parseGroupCode(grpParam)
      items <- gw.usersInGroup(code, acc, gcode).api
    yield items.map(toUser).toList
  }

  /* applications */

  private val listApplicationsRoute = endpoints.listApplications.implement { case (cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      items <- gw.applications().api
    yield items.map(toApp).toList
  }

  private val createApplicationRoute = endpoints.createApplication.implement { case (cookies, header, body) =>
    for
      s       <- session(header, cookies)
      _       <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      req      = morbid.protocol.CreateApplicationRequest(body.code, body.name)
      created <- gw.createApplication(req).api
    yield toApp(created)
  }

  private val updateApplicationRoute = endpoints.updateApplication.implement { case (cookies, header, body) =>
    for
      s       <- session(header, cookies)
      _       <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      req      = morbid.protocol.UpdateApplicationRequest(body.id, body.active, body.name)
      updated <- gw.updateApplication(req).api
    yield toApp(updated)
  }

  /* roles */

  private val listRolesRoute = endpoints.listRoles.implement { case (appParam, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      code  <- parseAppCode(appParam)
      items <- gw.rolesOfApp(code).api
    yield items.map(toRole).toList
  }

  /* tenants */

  private def parseTenantId(raw: String): IO[ApiError, TenantId] =
    ZIO.fromTry(Try(TenantId.of(raw.toLong))).mapError(_ => badInput(s"Invalid tenant id '$raw'"))

  private def parseProviderId(raw: String): IO[ApiError, ProviderId] =
    ZIO.fromTry(Try(ProviderId.of(raw.toLong))).mapError(_ => badInput(s"Invalid provider id '$raw'"))

  private def parseApplicationId(raw: String): IO[ApiError, ApplicationId] =
    ZIO.fromTry(Try(ApplicationId.of(raw.toLong))).mapError(_ => badInput(s"Invalid application id '$raw'"))

  private def toTenant(t: RawTenantDetails): TenantResponse = TenantResponse(t.id, t.code)

  private def toProvider(p: RawIdentityProvider): ProviderResponse =
    ProviderResponse(p.id, p.code, p.name, p.domain, p.kind, p.active, p.created)

  private def toApiKey(u: RawUserEntry): ApiKeyResponse =
    ApiKeyResponse(u.id, u.code, u.email, u.active, u.created)

  private val listTenantsRoute = endpoints.listTenants.implement { case (cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      items <- gw.tenants().api
    yield items.map(toTenant).toList
  }

  private val createTenantRoute = endpoints.createTenant.implement { case (cookies, header, body) =>
    for
      s   <- session(header, cookies)
      _   <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      req  = StoreTenantRequest(id = None, code = body.code, name = body.name, active = true)
      out <- gw.storeTenant(req).api
    yield toTenant(out)
  }

  private val updateTenantRoute = endpoints.updateTenant.implement { case (tn, cookies, header, body) =>
    for
      s   <- session(header, cookies)
      _   <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      id  <- parseTenantId(tn)
      req  = StoreTenantRequest(id = Some(id), code = body.code, name = body.name, active = body.active)
      out <- gw.updateTenant(id, req).api
    yield toTenant(out)
  }

  private val deleteTenantRoute = endpoints.deleteTenant.implement { case (tn, cookies, header) =>
    for
      s   <- session(header, cookies)
      _   <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      id  <- parseTenantId(tn)
      _   <- gw.removeTenant(id).api
    yield true
  }

  /* identity providers */

  private val listProvidersRoute = endpoints.listProviders.implement { case (acc, cookies, header, adminApp) =>
    for
      pair     <- readSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      items    <- gw.providersOfAccount(id).api
    yield items.map(toProvider).toList
  }

  private val createProviderRoute = endpoints.createProvider.implement { case (acc, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      req       = StoreIdentityProviderRequest(id = None, active = body.active, domain = body.domain, kind = body.kind, code = body.code, name = body.name)
      out      <- gw.storeProvider(id, req).api
    yield toProvider(out)
  }

  private val updateProviderRoute = endpoints.updateProvider.implement { case (acc, prv, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      accId    <- parseAccountId(acc)
      prvId    <- parseProviderId(prv)
      req       = StoreIdentityProviderRequest(id = Some(prvId), active = body.active, domain = body.domain, kind = body.kind, code = body.code, name = body.name)
      out      <- gw.updateProvider(accId, prvId, req).api
    yield toProvider(out)
  }

  private val deleteProviderRoute = endpoints.deleteProvider.implement { case (acc, prv, cookies, header, adminApp) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      accId    <- parseAccountId(acc)
      prvId    <- parseProviderId(prv)
      _        <- gw.removeProvider(accId, prvId).api
    yield true
  }

  /* api keys */

  private val listApiKeysRoute = endpoints.listApiKeys.implement { case (acc, cookies, header, adminApp) =>
    for
      pair     <- readSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      items    <- gw.listApiKeys(id).api
    yield items.map(toApiKey).toList
  }

  private val issueApiKeyRoute = endpoints.issueApiKey.implement { case (acc, cookies, header, adminApp, body) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      req       = CreateApiKeyRequest(email = body.email, name = body.name, days = body.days)
      out      <- gw.issueApiKey(id, req).api
    yield ApiKeyIssuedResponse(toApiKey(out.user), out.token)
  }

  private val deleteApiKeyRoute = endpoints.deleteApiKey.implement { case (acc, key, cookies, header, adminApp) =>
    for
      pair     <- writeSession(header, cookies, adminApp)
      (s, app)  = pair
      given RawToken        = s.raw
      given ApplicationCode = app
      id       <- parseAccountId(acc)
      code     <- parseUserCode(key)
      _        <- gw.removeApiKey(id, code).api
    yield true
  }

  /* application delete */

  private val deleteApplicationRoute = endpoints.deleteApplication.implement { case (appParam, cookies, header) =>
    for
      s  <- session(header, cookies)
      _  <- auth.requireAdminAnywhere(s)
      given RawToken = s.raw
      id <- parseApplicationId(appParam)
      _  <- gw.removeApplication(id).api
    yield true
  }

  /* account-apps: enable/disable apps per account */

  private val listAccountAppsRoute = endpoints.listAccountApps.implement { case (acc, cookies, header, adminApp) =>
    for
      pair    <- readSession(header, cookies, adminApp)
      (s, _)   = pair
      given RawToken = s.raw
      id      <- parseAccountId(acc)
      items   <- gw.accountApps(id).api
    yield items.map(toApp).toList
  }

  private val linkAccountAppRoute = endpoints.linkAccountApp.implement { case (acc, appParam, cookies, header, adminApp) =>
    for
      pair    <- writeSession(header, cookies, adminApp)
      (s, _)   = pair
      given RawToken = s.raw
      id      <- parseAccountId(acc)
      code    <- parseAppCode(appParam)
      _       <- gw.linkAccountApp(id, code).api
    yield true
  }

  private val unlinkAccountAppRoute = endpoints.unlinkAccountApp.implement { case (acc, appParam, cookies, header, adminApp) =>
    for
      pair    <- writeSession(header, cookies, adminApp)
      (s, _)   = pair
      given RawToken = s.raw
      id      <- parseAccountId(acc)
      code    <- parseAppCode(appParam)
      _       <- gw.unlinkAccountApp(id, code).api
    yield true
  }

  /* wiring */

  private val uefHeader = HandlerAspect.updateResponse { response =>
    if response.status.isError then response.addHeader(uef.UEFHeader) else response
  }

  private val typed = Routes(
    loginProviderRoute,
    whoamiRoute,
    listAccountsRoute, createAccountRoute, updateAccountRoute, deleteAccountRoute,
    listUsersRoute, createUserRoute, updateUserRoute, deleteUserRoute,
    changePasswordRoute, resetPasswordRoute, setPinRoute,
    listGroupsRoute, createGroupRoute, deleteGroupRoute, listGroupUsersRoute,
    listApplicationsRoute, createApplicationRoute, updateApplicationRoute, deleteApplicationRoute,
    listRolesRoute,
    listTenantsRoute, createTenantRoute, updateTenantRoute, deleteTenantRoute,
    listProvidersRoute, createProviderRoute, updateProviderRoute, deleteProviderRoute,
    listApiKeysRoute, issueApiKeyRoute, deleteApiKeyRoute,
    listAccountAppsRoute, linkAccountAppRoute, unlinkAccountAppRoute,
  ) @@ uefHeader

  private val open = Routes(
    Method.GET / "health" -> Handler.fromZIO(ZIO.succeed(Response.json("""{"status":"ok"}""")))
  ).sandbox

  override def routes: Routes[Any, Nothing] = open ++ loginWithCookie ++ logoffRoute ++ typed
}

object AdminRouter {
  val layer: ZLayer[AdminAuth & MorbidGateway & AppConfig, Nothing, Router] =
    ZLayer.fromFunction { (auth: AdminAuth, gw: MorbidGateway, cfg: AppConfig) =>
      AdminRouter(auth, gw, cfg): Router
    }
}
