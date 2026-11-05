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

  private def toLoginResponse(session: AdminSession): LoginResponse =
    LoginResponse(session.email, session.account, None)

  /* auth */

  private def errorResponse(err: ApiError): Response = {
    val status = Status.fromInt(err.uef.status)
    Response(status = status, body = Body.fromString(zio.json.EncoderOps(err.uef).toJson))
      .addHeader(uef.UEFHeader)
  }

  private val loginWithCookie: Routes[Any, Nothing] = Routes(
    Method.POST / "login" -> Handler.fromFunctionZIO[Request] { request =>
      val handle: ZIO[Any, Response, Response] = for
        raw   <- request.body.asString.mapError(e => errorResponse(badInput(s"Could not read body: ${e.getMessage}")))
        body  <- ZIO.fromEither(zio.json.JsonDecoder[LoginRequest].decodeJson(raw))
                   .mapError(err => errorResponse(badInput(err)))
        pair  <- auth.login(body.firebaseToken).mapError(errorResponse)
        (session, cookie) = pair
      yield Response.json(zio.json.EncoderOps(toLoginResponse(session)).toJson).addCookie(cookie)
      handle.merge
    }
  ).sandbox

  private val logoffRoute: Routes[Any, Nothing] = Routes(
    Method.POST / "logoff" -> Handler.fromFunctionZIO[Request] { request =>
      val resp     = Response.ok.addCookie(auth.logoutCookie)
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
      s <- session(header, cookies)
    yield toLoginResponse(s)
  }

  /* accounts */

  private val listAccountsRoute = endpoints.listAccounts.implement { case (cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      items <- gw.accounts().api
    yield items.map(toAccount).toList
  }

  private val createAccountRoute = endpoints.createAccount.implement { case (cookies, header, body) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      req    = StoreAccountRequest(id = None, tenant = body.tenant, name = body.name, code = body.code, active = body.active, update = false)
      acc   <- gw.storeAccount(req).api
    yield toAccount(acc)
  }

  private val updateAccountRoute = endpoints.updateAccount.implement { case (acc, cookies, header, body) =>
    for
      s        <- session(header, cookies)
      given RawToken = s.raw
      id       <- parseAccountId(acc)
      existing <- gw.accounts().api.map(_.find(_.id == id)).someOrFail(notFound(s"Account '$acc' not found"))
      req       = StoreAccountRequest(id = Some(id), tenant = existing.tenant, name = body.name, code = existing.code, active = body.active, update = true)
      updated  <- gw.storeAccount(req).api
    yield toAccount(updated)
  }

  private val deleteAccountRoute = endpoints.deleteAccount.implement { case (acc, cookies, header) =>
    for
      s  <- session(header, cookies)
      given RawToken = s.raw
      id <- parseAccountId(acc)
      _  <- gw.removeAccount(id).api
    yield true
  }

  /* users */

  private val listUsersRoute = endpoints.listUsers.implement { case (acc, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      id    <- parseAccountId(acc)
      items <- gw.usersOfAccount(id).api
    yield items.map(toUser).toList
  }

  private val createUserRoute = endpoints.createUser.implement { case (acc, cookies, header, body) =>
    for
      s    <- session(header, cookies)
      given RawToken = s.raw
      id   <- parseAccountId(acc)
      req   = StoreUserRequest(id = None, code = None, kind = body.kind, email = body.email, password = None, tenant = None, active = body.active, update = false)
      user <- gw.storeUserFor(id, req).api
    yield toUser(user)
  }

  private val updateUserRoute = endpoints.updateUser.implement { case (acc, usr, cookies, header, body) =>
    for
      s        <- session(header, cookies)
      given RawToken = s.raw
      id       <- parseAccountId(acc)
      code     <- parseUserCode(usr)
      current  <- gw.usersOfAccount(id).api.map(_.find(_.code == code)).someOrFail(notFound(s"User '$usr' not found"))
      req       = StoreUserRequest(id = Some(current.id), code = Some(current.code), kind = current.kind, email = body.email, password = None, tenant = None, active = body.active, update = true)
      updated  <- gw.storeUserFor(id, req).api
    yield toUser(updated)
  }

  private val deleteUserRoute = endpoints.deleteUser.implement { case (acc, usr, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      id    <- parseAccountId(acc)
      code  <- parseUserCode(usr)
      _     <- gw.removeUserFrom(id, code).api
    yield true
  }

  private val changePasswordRoute = endpoints.changePassword.implement { case (cookies, header, body) =>
    for
      s <- session(header, cookies)
      given RawToken = s.raw
      _ <- gw.passwordChange(ChangePasswordRequest(body.email, body.password)).api
    yield true
  }

  private val resetPasswordRoute = endpoints.resetPassword.implement { case (cookies, header, body) =>
    for
      s    <- session(header, cookies)
      given RawToken = s.raw
      link <- gw.passwordResetLink(RequestPasswordRequestLink(body.email)).api
    yield PasswordResetResponse(link.link)
  }

  private val setPinRoute = endpoints.setPin.implement { case (cookies, header, body) =>
    for
      s <- session(header, cookies)
      given RawToken = s.raw
      _ <- gw.setPin(SetUserPin(body.email, body.pin)).api
    yield true
  }

  /* groups */

  private val listGroupsRoute = endpoints.listGroups.implement { case (app, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      code  <- parseAppCode(app)
      items <- gw.groupsOfApp(code).api
    yield items.map(toGroup).toList
  }

  private val createGroupRoute = endpoints.createGroup.implement { case (app, cookies, header, body) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      code  <- parseAppCode(app)
      req    = StoreGroupRequest(id = None, code = body.code, name = body.name, users = body.users, roles = body.roles)
      group <- gw.storeGroup(code, req).api
    yield toGroup(group)
  }

  private val deleteGroupRoute = endpoints.deleteGroup.implement { case (app, grp, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      code  <- parseAppCode(app)
      gcode <- parseGroupCode(grp)
      _     <- gw.removeGroup(code, RemoveGroupRequest(gcode)).api
    yield true
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
      s   <- session(header, cookies)
      given RawToken = s.raw
      req  = morbid.protocol.CreateApplicationRequest(body.code, body.name)
      app <- gw.createApplication(req).api
    yield toApp(app)
  }

  private val updateApplicationRoute = endpoints.updateApplication.implement { case (cookies, header, body) =>
    for
      s   <- session(header, cookies)
      given RawToken = s.raw
      req  = morbid.protocol.UpdateApplicationRequest(body.id, body.active, body.name)
      app <- gw.updateApplication(req).api
    yield toApp(app)
  }

  /* roles */

  private val listRolesRoute = endpoints.listRoles.implement { case (app, cookies, header) =>
    for
      s     <- session(header, cookies)
      given RawToken = s.raw
      code  <- parseAppCode(app)
      items <- gw.rolesOfApp(code).api
    yield items.map(toRole).toList
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
    listGroupsRoute, createGroupRoute, deleteGroupRoute,
    listApplicationsRoute, createApplicationRoute, updateApplicationRoute,
    listRolesRoute,
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
