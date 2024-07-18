package morbid

import secure.{AppRoute, role, appRoute}
import accounts.AccountManager
import billing.Billing
import commands.*
import config.MorbidConfig
import domain.*
import domain.raw.*
import domain.requests.*
import domain.token.{Token, SingleAppToken}
import gip.*
import passwords.PasswordGenerator
import pins.PinManager
import repo.Repo
import proto.*
import tokens.*
import types.*
import utils.{errorToResponse, orFail, refineError}
import guara.utils.{ensureResponse, parse}
import guara.errors.*
import guara.router.Router
import guara.router.Echo
import zio.*
import zio.json.*
import zio.http.Cookie.SameSite
import zio.http.{Cookie, Handler, HttpApp, Method, Path, Request, Response, Routes, handler}
import zio.http.Middleware.{CorsConfig, cors}
import zio.http.codec.PathCodec.{long, string}
import io.scalaland.chimney.dsl.*

import scala.util.Random
import java.time.LocalDateTime

object cookies {

  val auth = Cookie.Response(
    name       = "morbid-auth",
    content    = "true",
    isHttpOnly = false,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  val token = Cookie.Response(
    name       = "morbid-token",
    content    = "",
    isHttpOnly = true,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  extension (r: Response) {
    def loggedIn(tk: String): Response = r.addCookie(auth).addCookie(token.copy(content = tk))
    def logOff              : Response = r.addCookie(auth.copy(maxAge = Some(0.seconds))).addCookie(token.copy(maxAge = Some(0.seconds)))
  }
}

object router {

  import cookies.*
  import roles.*
  import roles.given

  private val corsConfig =  CorsConfig()

  object MorbidRouter {
    val layer = ZLayer.fromFunction(MorbidRouter.apply _)
  }

  case class LoginSuccess(email: String, admin: Boolean)

  case class MorbidRouter(
    repo         : Repo,
    accounts     : AccountManager,
    billing      : Billing,
    cfg          : MorbidConfig,
    identities   : Identities,
    pins         : PinManager,
    passGen      : PasswordGenerator,
    tokens       : TokenGenerator
  ) extends Router {

    private def protect(r: AppRoute)(app: String, request: Request): Task[Response] = {
      appRoute(ApplicationCode.of(app), tokenFrom)(r)(request)
    }

    private def forbidden(cause: Throwable) = ReturnResponseError(Response.forbidden(s"Error verifying token: ${cause.getMessage}"))

    private def tokenFrom(request: Request): Task[Token] = {
      (request.headers.get("X-MorbidToken"), request.cookie("morbid-token")) match
        case (None, None     ) => ZIO.fail(Exception("Authorization cookie or header is missing"))
        case (Some(header), _) => tokens.verify(header)         .mapError(forbidden)
        case (_, Some(cookie)) => tokens.verify(cookie.content) .mapError(forbidden)
    }

    private def applicationDetailsGiven(request: Request): Task[Response] = ensureResponse {
      for {
        tk   <- tokenFrom(request)
        apps <- repo.exec(FindApplications(tk.user.details.accountCode))
      } yield Response.json(apps.toJson)
    }

    private def applicationGiven(app: String, request: Request): Task[Response] = {
      for {
        tk     <- tokenFrom(request)
        result <- repo.exec(FindApplication(tk.user.details.accountCode, ApplicationCode.of(app)))
      } yield result match
        case None              => Response.notFound
        case Some(application) => Response.json(application.toJson)
    }

    private def loginProvider(request: Request): Task[Response] = {

      def encode(provider: Option[RawIdentityProvider]): String = {
        provider match
          case None                                                                     => s"""{"type": "up"}"""
          case Some(RawIdentityProvider(_, _, _, _, _, _, ProviderKind.UP  , _, _))     => s"""{"type": "up"}"""
          case Some(RawIdentityProvider(_, _, _, _, _, _, ProviderKind.SAML, id, name)) => s"""{"type": "saml", "id": "$id", "name": "$name"}"""
      }

      ensureResponse {
        for {
          req      <- request.body.parse[GetLoginMode]
          provider <- identities.providerGiven(req.email, req.tenant)
        } yield Response.json(encode(provider))
      }
    }

    private def loginProviderForAccount(request: Request): Task[Response] = {
      def build(tk: Token, now: LocalDateTime, domain: Domain): RawIdentityProvider = {
        RawIdentityProvider(
          id      = ProviderId.of(0),
          created = now,
          deleted = None,
          account = tk.user.details.account,
          active  = true,
          domain  = domain,
          kind    = ProviderKind.UP,
          code    = ProviderCode.of(""),
          name    = ProviderName.of(""),
        )
      }

      for {
        token  <- tokenFrom(request)
        maybe  <- identities.providerGiven(token.user.details.account)
        domain <- token.user.details.email.domainName.orFail("Error extracting domain from user email")
        now    <- Clock.localDateTime
      } yield maybe match
        case None           => Response.json(build(token, now, domain).toJson)
        case Some(provider) => Response.json(provider.toJson)
    }

    private def loginResponse(token: Token, encoded: String) = {
      Response.json(token.toJson).loggedIn(encoded)
    }

    private def login(request: Request): Task[Response] = {

      def ensureUser(identity: CloudIdentity, maybeUser: Option[RawUser]): Task[RawUser] = {
        maybeUser match {
          case Some(user) => ZIO.succeed(user)
          case None       => accounts.provision(identity)
        }
      }

      ensureResponse {
        for {
          vgt       <- request.body.parse[VerifyGoogleTokenRequest]
          identity  <- identities.verify(vgt)
          maybeUser <- repo.exec(FindUserByEmail(identity.email))
          user      <- ensureUser(identity, maybeUser)
          token     <- tokens.asToken(user)
          encoded   <- tokens.encode(token)
        } yield loginResponse(token, encoded)
      }
    }

    private def logoff(request: Request): Task[Response] = {
      ZIO.succeed {
        Response.ok.logOff
      }
    }

    private def userBy(request: Request): Task[Response] = {

      val email = request.url.queryParams.get("email").map(Email.of)
      val id    = request.url.queryParams.get("id").map(_.toLong).map(UserId.of)

      def get(cmd: Command[Option[RawUser]]) = {
        for
          user <- repo.exec(cmd).mapError(Exception(s"Error searching for user (id:${id.getOrElse("_")}, email:${email.getOrElse("_")})", _))
        yield user match
          case Some(usr) => Response.json(usr.toJson)
          case None      => Response.notFound
      }

      (email, id) match
        case ( None, Some(id)    ) => get(FindUserById(id))
        case ( Some(email), None ) => get(FindUserByEmail(email))
        case ( Some(_), Some(_)  ) => ZIO.succeed(Response.badRequest("Please provider an ID or EMAIL. Not both"))
        case ( None, None        ) => ZIO.succeed(Response.badRequest("Please provider an ID or EMAIL"))
    }

    private def storeGroup: AppRoute = role("adm" or "group_adm") { request =>

      val token       = summon[SingleAppToken]
      val application = token.user.application.details.code

      def build(req: StoreGroupRequest, app: RawApplication, code: GroupCode, now: LocalDateTime) = {
        val group = RawGroup(
          id      = req.id.getOrElse(GroupId.of(0)),
          created = now,
          deleted = None,
          code    = code,
          name    = req.name
        )

        StoreGroup(
          account     = token.user.details.account,
          accountCode = token.user.details.accountCode,
          application = app,
          users       = req.users,
          roles       = req.roles,
          group       = group
        )
      }

      def uniqueCode: Task[GroupCode] = ZIO.attempt(GroupCode.of(Random.alphanumeric.take(16).mkString("")))

      (for
        now     <- Clock.localDateTime
        req     <- request.body.parse[StoreGroupRequest].mapError(err => ReturnResponseError(Response.badRequest(err.getMessage)))
        app     <- repo.exec(FindApplication(token.user.details.accountCode, application)).orFail(s"Can't find application '${application}'")
        code    <- req.code.map(ZIO.succeed).getOrElse(uniqueCode)
        _       <- ZIO.logInfo(s"Storing group '${req.name} (${req.id}/$code)' in app '${app.details.code}' in account '${token.user.details.account}' in tenant '${token.user.details.tenant}'")
        create  =  build(req, app, code, now)
        created <- repo.exec(create)
      yield Response.json(created.toJson)).errorToResponse(Response.internalServerError("Error creating group"))
    }

    private def storeUser: AppRoute = role("adm" or "user_adm") { request =>

      val token       = summon[SingleAppToken]
      val application = token.user.application.details.code

      def uniqueCode(email: Email): Task[UserCode] = {

        def attemptUnique(user: EmailUser, count: Int): Task[UserCode] = {

          def gen: Task[UserCode] = ZIO.attempt(UserCode.of(Random.alphanumeric.take(16).mkString("")))

          for {
            _      <- ZIO.when(count > 10) { ZIO.fail(new Exception("Can't generate user code. Too many attempts")) }
            tmp    <- gen
            exists <- repo.exec(UserExists(tmp))
            code   <- if(exists) attemptUnique(user, count + 1) else ZIO.succeed(tmp)
          } yield code
        }

        email.userName match
          case None       => ZIO.fail(new Exception(s"Error generating code from '$email'"))
          case Some(user) => attemptUnique(user, 0)
      }

      def buildRequest(req: StoreUserRequest, account: RawAccount, code: UserCode) =
        req
          .into[StoreUser]
          .withFieldConst(_.id, req.id.getOrElse(UserId.of(0)))
          .withFieldConst(_.account, account)
          .withFieldConst(_.code, code)
          .withFieldConst(_.update, req.update.getOrElse(false))
          .transform

      for
        req    <- request.body.parse[StoreUserRequest].mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        pwd    <- ZIO.fromOption(req.password) .orElse(passGen.generate).errorToResponse(Response.internalServerError("Error generating user code"))
        code   <- ZIO.fromOption(req.code)     .orElse(uniqueCode(req.email))
        acc    <- repo.exec(FindAccountByCode(token.user.details.accountCode)).orFail(s"Can't find account '${token.user.details.accountCode}'")
        store  = buildRequest(req, acc, code)
        _      <- ZIO.logInfo(s"Storing user '${store.email}/${store.id}' in account '${store.account.id}' in tenant '${store.account.tenantCode}' (update ? ${store.update})")
        user   <- repo.exec(store).refineError(s"Error storing user '${store.email}'")
        _      <- ZIO.logInfo(s"User '${user.email}/${user.id}' stored")
        _      <- identities.createUser(store, pwd).refineError("Error storing user identity")
      yield Response.json(user.toJson)
    }

    private def removeUser: AppRoute = role("adm" or "user_adm") { request =>

      val token   = summon[SingleAppToken]
      val account = token.user.details.account

      for
        req    <- request.body.parse[RemoveUserRequest].mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        result <- repo.exec(RemoveUser(account, req.code))
      yield Response.json(result.toJson)
    }

    private def removeGroup: AppRoute = role("adm" or "group_adm") { request =>

      val token       = summon[SingleAppToken]
      val account     = token.user.details.account
      val application = token.user.application.details.id

      for
        req    <- request.body.parse[RemoveGroupRequest].mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        result <- repo.exec(RemoveGroup(account, application, req.code))
      yield Response.json(result.toJson)
    }

    private def usersGiven: AppRoute = role("adm" or "user_adm") { request =>
      val token       = summon[SingleAppToken]
      val application = token.user.application.details.code
      usersGiven(request, application, None)
    }

    private def validateUserPin(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[ValidateUserPin]
        token <- tokenFrom(request)
        uid   =  token.impersonatedBy.map(_.id).getOrElse(token.user.details.id)
        valid <- pins.validate(uid, req.pin)
      } yield if(valid) Response.ok else Response.forbidden
    }

    private def verify(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[VerifyMorbidTokenRequest].mapError(forbidden)
        token <- tokens.verify(req.token)                    .mapError(forbidden)
      } yield Response.json(token.toJson)
    }

    private def impersonate(request: Request): Task[Response] = ensureResponse {
      for {
        impersonator <- tokenFrom(request)
        req          <- request.body.parse[ImpersonationRequest]
        same         =  req.magic.is(cfg.magic.password)
        _            <- ZIO.when(!same) { ZIO.fail(new Exception("Bad Magic")) }
        user         <- repo.exec(FindUserByEmail(req.email))
        token        <- user match {
                          case Some(usr) => tokens.asToken(usr)
                          case None      => ZIO.fail(ReturnResponseError(Response.notFound(s"user ${req.email} not found")))
                        }
        _            <- ZIO.logInfo(s"User '${token.user.details.email}' impersonated by ${impersonator.user.details.email}")
        impersonated = token.copy(impersonatedBy = Some(impersonator.user.details))
        encoded      <- tokens.encode(impersonated)
      } yield loginResponse(impersonated, encoded)
    }

    private def usersGiven(request: Request, application: ApplicationCode, group: Option[GroupCode] = None): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- repo.exec(FindUsersInGroup(tk.user.details.accountCode, application, group))
      } yield Response.json(seq.toJson)
    }

    private def groupUsers(app: String, group: String, request: Request): Task[Response] = usersGiven(request, ApplicationCode.of(app), Some(GroupCode.of(group)))

    private def groupsGiven(app: String, request: Request): Task[Response] = ensureResponse {
      val appCode = ApplicationCode.of(app)
      for {
        tk     <- tokenFrom(request)
        filter =  request.url.queryParams.getAll("code").getOrElse(Seq.empty).map(GroupCode.of)
        map    <- repo.exec(FindGroups(tk.user.details.accountCode, Seq(appCode), filter))
      } yield map.get(appCode) match
        case Some(groups) => Response.json(groups.toJson)
        case None         => Response.notFound(s"Can't find groups for '$app'")
    }

    private def rolesGiven(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- repo.exec(FindRoles(tk.user.details.accountCode, ApplicationCode.of(app)))
      } yield Response.json(seq.toJson)
    }

    private def sameUserOr[T <: HasEmail, R](role: Role)(fn: (SingleAppRawUser, T) => Task[R])(request: Request)(using token: SingleAppToken)(using JsonDecoder[T], JsonEncoder[R]): Task[Response] = ensureResponse {

      def ifAdmLoadUserSameAccount(token: SingleAppToken, req: T): Task[SingleAppRawUser] = {

        def badRequest(reason: String) = ZIO.fail(ReturnResponseError(Response.badRequest(s"Can't find user '${req.email}' ($reason)")))

        val application = token.user.application.details.code
        val isAdm       = role.isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { badRequest("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe).mapError(_ => ReturnResponseError(Response.notFound(s"Can't find user '${req.email}'")))
          narrowed    <- ZIO.fromOption(user.narrowTo(application)).mapError(_ => ReturnResponseError(Response.forbidden(s"User '${req.email}' has no access to application '${application}'")))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { badRequest("other account") }
        yield narrowed
      }

      for {
        req    <- request.body.parse[T]
        me     =  token.user.details.email == req.email
        user   <- if (me) ZIO.succeed(token.user) else ifAdmLoadUserSameAccount(token, req)
        result <- fn(user, req)
      } yield Response.json(result.toJson)
    }

    private def setUserPin: AppRoute = sameUserOr[SetUserPin, Boolean]("adm" or "user_adm") { (user, req) =>
      for {
        _ <- ZIO.logInfo(s"Setting pin for '${user.details.email}'")
        _ <- pins.set(user.details.id, req.pin)
      } yield true
    }

    private def passwordResetLink: AppRoute = sameUserOr[RequestPasswordRequestLink, PasswordResetLink]("adm" or "user_adm") { (user, req) =>
      for
        _    <- ZIO.logInfo(s"Generating password reset link for '${req.email}'")
        link <- identities.passwordResetLink(req.email).map(PasswordResetLink.apply)
      yield link
    }

    private def setUserPinToBeRemoved(request: Request)(using application: ApplicationCode): Task[Response] = ensureResponse {

      def changeMyPin(token: Token): Task[UserId] = ZIO.succeed(token.user.details.id)

      def changeSomebodyElse(token: Token, req: SetUserPin): Task[UserId] = {

        def badRequest(reason: String) = ZIO.fail(ReturnResponseError(Response.badRequest(s"Can't reset PIN for '${req.email}' ($reason)")))

        val isAdm =  ("adm" or "user_adm").isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { badRequest("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe).mapError(_ => ReturnResponseError(Response.notFound(s"Can't find user '${req.email}'")))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { badRequest("other account") }
        yield user.details.id
      }

      for {
        req   <- request.body.parse[SetUserPin]
        token <- tokenFrom(request)
        me    =  token.user.details.email == req.email
        id    <- if (me) changeMyPin(token) else changeSomebodyElse(token, req)
        _     <- pins.set(id, req.pin)
      } yield Response.json(true.toJson)
    }

    private def passwordResetLinkToBeRemoved(request: Request)(using application: ApplicationCode): Task[Response] = ensureResponse {

      def changeMyPassword(token: Token, req: RequestPasswordRequestLink): Task[Email] = ZIO.succeed(token.user.details.email)

      def changeSomebodyElse(token: Token, req: RequestPasswordRequestLink): Task[Email] = {

        def badRequest(reason: String) = ZIO.fail(ReturnResponseError(Response.badRequest(s"Can't reset password for '${req.email}' ($reason)")))

        val isAdm =  ("adm" or "user_adm").isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { badRequest("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe).mapError(_ => ReturnResponseError(Response.notFound(s"Can't find user '${req.email}'")))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { badRequest("other account") }
        yield req.email
      }

      for
        token <- tokenFrom(request)
        req   <- request.body.parse[RequestPasswordRequestLink]
        me    =  token.user.details.email == req.email
        email <- if (me) changeMyPassword(token, req) else changeSomebodyElse(token, req)
        link  <- identities.passwordResetLink(email)
      yield Response.json(PasswordResetLink(link).toJson)

    }

    private def regular = Routes(
      Method.GET    / "applications"                               -> Handler.fromFunctionZIO[Request](applicationDetailsGiven),
      Method.GET    / "application" / string("app")                -> handler(applicationGiven),
      Method.POST   / "login" / "provider"                         -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.GET    / "login" / "provider"                         -> Handler.fromFunctionZIO[Request](loginProviderForAccount),
      Method.POST   / "login"                                      -> Handler.fromFunctionZIO[Request](login),
      Method.POST   / "logoff"                                     -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST   / "verify"                                     -> Handler.fromFunctionZIO[Request](verify),
      Method.POST   / "impersonate"                                -> Handler.fromFunctionZIO[Request](impersonate),
      Method.GET    / "user"                                       -> Handler.fromFunctionZIO[Request](userBy),
      Method.POST   / "user" / "pin" / "validate"                  -> Handler.fromFunctionZIO[Request](validateUserPin),
      Method.POST   / "app" / string("app") / "user" / "pin"       -> handler(protect(setUserPin)),
      Method.POST   / "app" / string("app") / "password" / "reset" -> handler(protect(passwordResetLink)),
      Method.GET    / "app" / string("app") / "users"              -> handler(protect(usersGiven)),
      Method.POST   / "app" / string("app") / "user"               -> handler(protect(storeUser)),
      Method.POST   / "app" / string("app") / "user"  / "delete"   -> handler(protect(removeUser)),
      Method.GET    / "app" / string("app") / "groups"             -> handler(groupsGiven),
      Method.POST   / "app" / string("app") / "group"              -> handler(protect(storeGroup)),
      Method.POST   / "app" / string("app") / "group" / "delete"   -> handler(protect(removeGroup)),
      Method.GET    / "app" / string("app") / "group"  / string("code") / "users" -> handler(groupUsers),
      Method.GET    / "app" / string("app") / "roles" -> handler(rolesGiven),
    ).sandbox.toHttpApp

    override def routes: HttpApp[Any] = Echo.routes ++ regular @@ cors(corsConfig)
  }
}