package morbid

import guara.errors.*
import guara.router.{Echo, Router}
import guara.utils.{Origin, ensureResponse, parse}
import io.scalaland.chimney.dsl.*
import morbid.accounts.AccountManager
import morbid.billing.Billing
import morbid.commands.*
import morbid.config.MorbidConfig
import morbid.domain.*
import morbid.domain.raw.*
import morbid.domain.requests.*
import morbid.domain.token.{SingleAppToken, SingleAppUser, Token}
import morbid.gip.*
import morbid.passwords.PasswordGenerator
import morbid.pins.PinManager
import morbid.proto.*
import morbid.repo.Repo
import morbid.secure.{AppRoute, appRoute, role}
import morbid.tokens.*
import morbid.types.*
import morbid.utils.{asCommonError, errorToResponse, orFail}
import org.apache.commons.lang3.RandomStringUtils
import zio.*
import zio.http.*
import zio.http.Cookie.SameSite
import zio.http.Middleware.{CorsConfig, cors}
import zio.http.codec.PathCodec.string
import zio.json.*

import java.time.LocalDateTime
import scala.util.{Failure, Random, Success}

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
  import guara.utils.get
  import roles.{*, given}

  private val corsConfig = CorsConfig()
  private val GroupAll   = GroupCode.of("all")
  private given Origin   = Origin.of("MorbidServer")

  object MorbidRouter {
    val layer = ZLayer.fromFunction(MorbidRouter.apply _)
  }

  case class LoginSuccess(email: String, admin: Boolean)

  case class MorbidRouter(
    repo       : Repo,
    accounts   : AccountManager,
    billing    : Billing,
    cfg        : MorbidConfig,
    identities : Identities,
    pins       : PinManager,
    passGen    : PasswordGenerator,
    tokens     : TokenGenerator
  ) extends Router {

    private def protect(r: AppRoute)(app: String, request: Request): Task[Response] = {
      appRoute(ApplicationCode.of(app), tokenFrom)(r)(request)
    }

    private def forbidden(cause: Throwable) = ReturnResponseError(Response.forbidden(s"Error verifying token: ${cause.getMessage}"))

    private def testServiceToken(request: Request) = {

      def test(value: String) = ZIO.when(cfg.service.token != value) {
        ZIO.fail(ReturnResponseError(Response.unauthorized("Bad Authorization")))
      }

      (request.headers.get("X-Morbid-Service-Token"), request.cookie("morbid-service-token")) match
        case (None, None)      => ZIO.fail(ReturnResponseError(Response.unauthorized("Authorization cookie or header is missing")))
        case (Some(header), _) => test(header)
        case (_, Some(cookie)) => test(cookie.content)
    }

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
          req      <- request.body.parse[GetLoginMode]()
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
          case None       => accounts.provision(identity).mapError(err => Exception(s"Error provisioning user account for '${identity.email}': ${err.getMessage}", err))
        }
      }

      ensureResponse {
        for {
          vgt       <- request.body.parse[VerifyGoogleTokenRequest]() .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error parsing VerifyGoogleTokenRequest: ${err.getMessage}")))
          identity  <- identities.verify(vgt)                         .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error verifying firebase token '${vgt.token}: ${err.getMessage}'")))
          maybeUser <- repo.exec(FindUserByEmail(identity.email))     .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error locating user '${identity.email}': ${err.getMessage}'")))
          user      <- ensureUser(identity, maybeUser)                .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error ensuring user '${identity.email}': ${err.getMessage}'")))
          token     <- tokens.asToken(user)                           .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error creating token '${identity.email}': ${err.getMessage}'")))
          encoded   <- tokens.encode(token)                           .mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error encoding token '${identity.email}': ${err.getMessage}'")))
        } yield loginResponse(token, encoded)
      }
    }

    private def loginViaEmailLink(app: String, request: Request): Task[Response] = {
      ensureResponse {
        for {
          req       <- request.body.parse[LoginViaEmailLinkRequest]()
          maybeUser <- repo.exec(FindUserByEmail(req.email))
          _         <- ZIO.fromOption(maybeUser)                         .mapError(_   => ReturnResponseError(Response.notFound(s"Can't find user '${req.email}'")))
          link      <- identities.signInWithEmailLink(req.email, req.url).mapError(err => ReturnResponseWithExceptionError(err, Response.internalServerError(s"Error generating login link for '${req.email}'")))
        } yield Response.json(LoginViaEmailLinkResponse(link).toJson)
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
      val application = token.user.application.code

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
        req     <- request.body.parse[StoreGroupRequest]().mapError(err => ReturnResponseError(Response.badRequest(err.getMessage)))
        app     <- repo.exec(FindApplication(token.user.details.accountCode, application)).orFail(s"Can't find application '${application}'")
        code    <- req.code.map(ZIO.succeed).getOrElse(uniqueCode)
        _       <- ZIO.logInfo(s"Storing group '${req.name} (${req.id}/$code)' in app '${app.details.code}' in account '${token.user.details.account}' in tenant '${token.user.details.tenant}'")
        create  =  build(req, app, code, now)
        created <- repo.exec(create)
      yield Response.json(created.toJson)).errorToResponse(Response.internalServerError("Error creating group"))
    }

    private def storeUser: AppRoute = role("adm" or "user_adm") { request =>

      val token       = summon[SingleAppToken]
      val application = token.user.application

      def buildRequest(req: StoreUserRequest, account: RawAccount, code: String) =
        req
          .into[StoreUser]
          .withFieldConst(_.id     , req.id.getOrElse(UserId.of(0)))
          .withFieldConst(_.account, account)
          .withFieldConst(_.code   , UserCode.of(code)) // From firebase
          .withFieldConst(_.update , req.update.getOrElse(false))
          .transform

      def whenNewUser(acc: RawAccount, user: RawUserEntry) = {

        def link(groupsByApp: Map[ApplicationCode, Seq[RawGroup]], user: RawUserEntry): Task[Unit] = {

          def linkTo(group: RawGroup): Task[Unit] = {
            repo.exec {
              LinkUsersToGroup(
                application = application.id,
                group       = group.id,
                users       = Seq(user.id)
              )
            }
          }

          groupsByApp.get(application.code) match {
            case Some(Seq(group)) if group.code == GroupAll => linkTo(group)
            case _                                          => ZIO.fail(Exception(s"Can't find group '${GroupAll}' for application '${application.code}'"))
          }
        }

        for
          groups <- repo.exec(FindGroups(acc.code, Seq(application.code), Seq(GroupAll)))
          _      <- link(groups, user).asCommonError(10012, "Error adding user to group ALL")
        yield ()
      }

      def handleFirebaseUser(req: StoreUserRequest, acc: RawAccount, pass: Password) = {
        (req.id, req.update) match
          case (Some(_), Some(false)) | (Some(_), None) => identities.createUser(req.email, acc.tenantCode, pass).asCommonError(10011, "Error storing user identity")
          case (Some(_), Some(true))                    => identities.getUserByEmail(req.email, acc.tenantCode)
          case (None   , _)                             => ZIO.fail(Exception(s"User id not provided"))
      }

      for
        req    <- request.body.parse[StoreUserRequest]().mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        acc    <- repo.exec(FindAccountByCode(token.user.details.accountCode)).orFail(s"Can't find account '${token.user.details.accountCode}'")
        pass   = Password.of(RandomStringUtils.secure().nextAlphanumeric(10))
        fbUser <- handleFirebaseUser(req, acc, pass)
        store  =  buildRequest(req, acc, fbUser.getUid)
        _      <- ZIO.logInfo(s"Storing user ${store.id} - ${store.email} || Account ${store.account.id} || Tenant ${store.account.tenantCode} || Update: ${store.update}")
        user   <- repo.exec(store).asCommonError(10010, s"Error storing user '${store.email}'")
        _      <- ZIO.logInfo(s"User ${user.id} - ${user.email} stored")
        _      <- ZIO.when(req.id.isEmpty) { whenNewUser(acc, user) }
      yield Response.json(user.toJson)
    }

    private def removeUser: AppRoute = role("adm" or "user_adm") { request =>

      val token   = summon[SingleAppToken]
      val account = token.user.details.account

      for
        req    <- request.body.parse[RemoveUserRequest]().mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        result <- repo.exec(RemoveUser(account, req.code))
      yield Response.json(result.toJson)
    }

    private def removeGroup: AppRoute = role("adm" or "group_adm") { request =>

      val token       = summon[SingleAppToken]
      val account     = token.user.details.account
      val application = token.user.application.id

      for
        req    <- request.body.parse[RemoveGroupRequest]().mapError(e => ReturnResponseWithExceptionError(e, Response.badRequest(e.getMessage)))
        result <- repo.exec(RemoveGroup(account, application, req.code))
      yield Response.json(result.toJson)
    }

    private def usersGiven: AppRoute = role("adm" or "user_adm") { request =>
      val token       = summon[SingleAppToken]
      val application = token.user.application.code
      usersGiven(request, application, None)
    }

    private def validateUserPin(request: Request): Task[Response] = ensureResponse {

      def res(status: Status, text: String) = Response(status = status, body = Body.fromString(text))

      for {
        req   <- request.body.parse[ValidateUserPin]()
        token <- tokenFrom(request)
        uid   =  token.impersonatedBy.map(_.id).getOrElse(token.user.details.id)
        valid <- pins.validate(uid, req.pin)
      } yield if(valid) res(Status.Ok, "true") else res(Status.Forbidden, "false")
    }

    private def verify(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[VerifyMorbidTokenRequest]().mapError(forbidden)
        token <- tokens.verify(req.token)                      .mapError(forbidden)
      } yield Response.json(token.toJson)
    }

    private def impersonate(request: Request): Task[Response] = ensureResponse {
      for {
        impersonator <- tokenFrom(request)
        req          <- request.body.parse[ImpersonationRequest]()
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
        filter =  request.url.queryParams.getAll("code").map(GroupCode.of)
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

    private def sameUserOr[T <: HasEmail, R](role: Role)(fn: (SingleAppUser, T) => Task[R])(request: Request)(using token: SingleAppToken)(using JsonDecoder[T], JsonEncoder[R]): Task[Response] = ensureResponse {

      def ifAdmLoadUserSameAccount(token: SingleAppToken, req: T): Task[SingleAppUser] = {

        def badRequest(reason: String) = ZIO.fail(ReturnResponseError(Response.badRequest(s"Can't find user '${req.email}' ($reason)")))

        val application = token.user.application.code
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
        req    <- request.body.parse[T]()
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

    private def changePassword: AppRoute = sameUserOr[ChangePasswordRequest, Boolean]("adm" or "user_adm") { (user, req) =>
      val email = user.details.email
      for
        _ <- ZIO.logInfo(s"Changing password for '$email'")
        _ <- ZIO.when(!req.password.isValid) { ZIO.fail(Exception(s"Password for user '$email' is not valid")) }
        _ <- identities.changePassword(email, req.password)
      yield true
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
        req   <- request.body.parse[SetUserPin]()
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
        req   <- request.body.parse[RequestPasswordRequestLink]()
        me    =  token.user.details.email == req.email
        email <- if (me) changeMyPassword(token, req) else changeSomebodyElse(token, req)
        link  <- identities.passwordResetLink(email)
      yield Response.json(PasswordResetLink(link).toJson)

    }

    private def provisionAccount: AppRoute = role("adm") { request =>

      val Presto = summon[ApplicationCode]

      def createGroups(now: LocalDateTime, app: RawApplication, acc: RawAccount): Task[Seq[RawGroup]] = {

        val groups = Seq(
          RawGroup(id = GroupId.of(0), created = now, deleted = None, code = GroupCode.all  , name = GroupName.of("Todos"), roles = Seq.empty),
          RawGroup(id = GroupId.of(0), created = now, deleted = None, code = GroupCode.admin, name = GroupName.of("Admin"), roles = Seq.empty)
        )

        val commands = groups.map { group =>
          val roles = if(group.code == GroupCode.admin) Seq(RoleCode.of("adm")) else Seq.empty
          StoreGroup(account = acc.id, accountCode = acc.code, application = app, group = group, users = Seq.empty, roles = roles)
        }

        ZIO.foreach(commands) {
          repo.exec
        }
      }

      for {
        req     <- request.body.parse[CreateAccount]()
        _       <- ZIO.logInfo(s"Account Provisioning '${req.email}'")
        maybe   <- repo.exec(FindApplicationDetails(Presto))
        details <- ZIO.fromOption(maybe).mapError(_ => Exception(s"Can't find application '$Presto'"))
        acc     <- repo.exec(req.transformInto[StoreAccount])
        app     =  RawApplication(details)
        _       <- repo.exec(LinkAccountToApp(acc.id,  app.details.id))
        now     <- Clock.localDateTime
        groups  <- createGroups(now, app, acc)
        admin   <- ZIO.fromOption(groups.find(_.code == GroupCode.admin).map(_.id)).mapError(_ => Exception("Can't find group 'admin' after account creation"))
        all     <- ZIO.fromOption(groups.find(_.code == GroupCode.all)  .map(_.id)).mapError(_ => Exception("Can't find group 'all' after account creation"))
        fbUser  <- identities.createUser(req.email, acc.tenantCode, Password.of(RandomStringUtils.secure().nextAlphanumeric(10)))
        store   = StoreUser(id = req.user, email = req.email, code = UserCode.of(fbUser.getUid), account = acc, kind = None, update = false, active = true)
        user    <- repo.exec(store)
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = admin, users = Seq(user.id)))
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = all  , users = Seq(user.id)))
        created <- repo.exec(FindUserById(user.id))
      } yield created match
        case None        => Response.internalServerError(s"Error provisioning account ${req.email}")
        case Some(value) => Response.json(value.toJson)
    }

    private def provisionUsers: AppRoute = role("adm") { request =>

      val appCode = summon[ApplicationCode]

      for {
        form    <- request.body.asMultipartForm
        code    <- ZIO.fromOption(form.get("account")).mapError(_ => Exception("No field called 'account'"))
        file    <- ZIO.fromOption(form.get("file"))   .mapError(_ => Exception("No field called 'file'"))
        value   <- code.asText
        text    <- file.asText
        acc     <- repo.get(FindAccountByCode(AccountCode.of(value))) { s"Can't find account '$value'" }
        app     <- repo.get(FindApplicationDetails(appCode))          { s"Can't find application '$appCode' "}
        groups  <- repo.exec(FindGroups(account = acc.code, apps = Seq(appCode)))
        group   <- ZIO.fromOption(groups.get(appCode).flatMap(_.find(_.code == GroupCode.all))).mapError(_ => Exception(s"Can't find group '${GroupCode.all}' in account '${acc.id}'"))
        entries <- accounts.parseCSV(acc, text)
        created =  entries.map(_._2).filter(_.isSuccess).map(_.get).map(_.id)
        _       <- repo.exec(LinkUsersToGroup(app.id, group.id, created))
      } yield Response.json {
        entries.map {
          case (email, Success(user)) => (Email.value(email), s"[ok] ${user.id}")
          case (email, Failure(err))  => (Email.value(email), s"[err] ${err.getMessage}")
        }.toMap.toJson
      }
    }

    private def entitiesByApp[R](request: Request, command: Command[R])(using JsonCodec[R]) = ensureResponse {
      for
        _   <- testServiceToken(request)
        res <- repo.exec(command)
      yield Response.json(res.toJson)
    }

    private def accountsByApp(app: String, request: Request) = {
      entitiesByApp(request, FindAccountsByApp(ApplicationCode.of(app)))
    }

    private def usersByApp(app: String, request: Request) = {
      entitiesByApp(request, FindUsersByApp(ApplicationCode.of(app)))
    }

    private def serviceRoutes = Routes(
      Method.GET / "service" / "app" / string("app") /"users"    -> handler(usersByApp),
      Method.GET / "service" / "app" / string("app") /"accounts" -> handler(accountsByApp),
    ).sandbox

    private def regular = Routes(
      Method.GET  / "applications"                                              -> Handler.fromFunctionZIO[Request](applicationDetailsGiven),
      Method.GET  / "application" / string("app")                               -> handler(applicationGiven),
      Method.POST / "login" / "provider"                                        -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.GET  / "login" / "provider"                                        -> Handler.fromFunctionZIO[Request](loginProviderForAccount),
      Method.POST / "login"                                                     -> Handler.fromFunctionZIO[Request](login),
      Method.POST / "logoff"                                                    -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST / "verify"                                                    -> Handler.fromFunctionZIO[Request](verify),
      Method.POST / "impersonate"                                               -> Handler.fromFunctionZIO[Request](impersonate),
      Method.GET  / "user"                                                      -> Handler.fromFunctionZIO[Request](userBy),
      Method.POST / "user" / "pin" / "validate"                                 -> Handler.fromFunctionZIO[Request](validateUserPin),
      Method.POST / "app" / string("app") / "login" / "email"                   -> handler(loginViaEmailLink),
      Method.POST / "app" / string("app") / "user" / "pin"                      -> handler(protect(setUserPin)),
      Method.POST / "app" / string("app") / "password" / "reset"                -> handler(protect(passwordResetLink)),
      Method.POST / "app" / string("app") / "password" / "change"               -> handler(protect(changePassword)),
      Method.GET  / "app" / string("app") / "users"                             -> handler(protect(usersGiven)),
      Method.POST / "app" / string("app") / "user"                              -> handler(protect(storeUser)),
      Method.POST / "app" / string("app") / "user"  / "delete"                  -> handler(protect(removeUser)),
      Method.GET  / "app" / string("app") / "groups"                            -> handler(groupsGiven),
      Method.POST / "app" / string("app") / "group"                             -> handler(protect(storeGroup)),
      Method.POST / "app" / string("app") / "group" / "delete"                  -> handler(protect(removeGroup)),
      Method.GET  / "app" / string("app") / "group"  / string("code") / "users" -> handler(groupUsers),
      Method.GET  / "app" / string("app") / "roles"                             -> handler(rolesGiven),
      Method.POST / "app" / string("app") / "account"                           -> handler(protect(provisionAccount)),
      Method.POST / "app" / string("app") / "account" / "users"                 -> handler(protect(provisionUsers))
    ).sandbox

    override def routes = Echo.routes ++ regular ++ serviceRoutes @@ cors(corsConfig)
  }
}