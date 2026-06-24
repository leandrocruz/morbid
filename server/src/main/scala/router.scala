package morbid

import guara.errors.*
import guara.router.{Echo, Router}
import guara.utils.SafeResponse.*
import guara.utils.{Origin, ensureResponse, parse}
import io.scalaland.chimney.dsl.*
import morbid.MorbidError.*
import morbid.accounts.AccountManager
import morbid.commands.*
import morbid.config.MorbidConfig
import morbid.domain.*
import morbid.domain.raw.*
import morbid.domain.requests.*
import morbid.domain.token.{SingleAppToken, SingleAppUser, Token}
import morbid.gip.*
import morbid.legacy.{CreateLegacyAccountRequest, CreateLegacyUserRequest, LegacyMorbid, LegacyUser}
import morbid.passwords.PasswordGenerator
import morbid.pins.PinManager
import morbid.proto.*
import morbid.repo.Repo
import morbid.secure.{AppRoute, appRoute, role}
import morbid.tokens.*
import morbid.types.*
import morbid.utils.*
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
    name       = morbid.MorbidCookies.Auth,
    content    = "true",
    maxAge     = Some(1.days),
    isHttpOnly = false,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  val token = Cookie.Response(
    name       = morbid.MorbidCookies.Token,
    content    = "",
    maxAge     = Some(1.days),
    isHttpOnly = true,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  val original = Cookie.Response(
    name       = morbid.MorbidCookies.OriginalToken,
    content    = "",
    maxAge     = Some(1.days),
    isHttpOnly = true,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  private val clearedOriginal = original.copy(maxAge = Some(0.seconds))

  extension (r: Response) {
    def loggedIn(tk: String)        : Response = r.addCookie(auth).addCookie(token.copy(content = tk))
    def stashOriginal(tk: String)   : Response = r.addCookie(original.copy(content = tk))
    def clearOriginal               : Response = r.addCookie(clearedOriginal)
    def logOff                      : Response = r.addCookie(auth.copy(maxAge = Some(0.seconds))).addCookie(token.copy(maxAge = Some(0.seconds))).addCookie(clearedOriginal)
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
    cfg        : MorbidConfig,
    identities : Identities,
    pins       : PinManager,
    passGen    : PasswordGenerator,
    tokens     : TokenGenerator,
    legacy     : LegacyMorbid,
  ) extends Router {

    private def protect(r: AppRoute)(app: String, request: Request): Task[Response] = {
      ensureResponse(appRoute(ApplicationCode.of(app), tokenFrom)(r)(request)).toTask
    }

    private def forbidden(cause: Throwable) = GuaraError.of(Forbidden, Status.Forbidden, s"Error verifying token")(cause)

    private def ensureMagic(magic: Magic) = {
      ZIO.when(!cfg.magic.isValid(magic)) {
        ZIO.logWarning("bad magic") *> errors.badMagic
      }
    }

    private def testServiceToken(request: Request) = {

      def test(value: String) = {
        for
          _ <- ZIO.when(cfg.service.token != value) { errors.notAuthorized("Bad Authorization") }
        yield ()
      }

      (request.headers.get(morbid.MorbidHeaders.ServiceToken), request.cookie(morbid.MorbidCookies.ServiceToken)) match
        case (None, None)      => errors.notAuthorized("Authorization cookie or header is missing")
        case (Some(header), _) => test(header)
        case (_, Some(cookie)) => test(cookie.content)
    }

    private def rawTokenFrom(request: Request): Option[String] = {
      request.headers.get(morbid.MorbidHeaders.Token).orElse(request.cookie(morbid.MorbidCookies.Token).map(_.content))
    }

    private def tokenFrom(request: Request): Task[Token] = {
      rawTokenFrom(request) match
        case None      => errors.notAuthorized("Authorization cookie or header is missing")
        case Some(raw) => tokens.verify(raw).mapError(forbidden)
    }

    private def applicationDetailsGiven(request: Request): Task[Response] = ensureResponse {
      for {
        tk   <- tokenFrom(request)
        apps <- repo.exec(FindApplications(tk.user.details.accountCode))
      } yield Response.json(apps.toJson)
    }.toTask

    private def applicationGiven(app: String, request: Request): Task[Response] = {
      for {
        tk     <- tokenFrom(request)
        result <- repo.exec(FindApplication(tk.user.details.accountCode, ApplicationCode.of(app)))
      } yield result match
        case None              => Response.notFound
        case Some(application) => Response.json(application.toJson)
    }

    // Public: pricing/signup pages need to fetch the plan catalog before the user is authenticated.
    private def plansByApp(app: String, request: Request): Task[Response] = {
      for
        plans <- repo.exec(FindPlansForApp(ApplicationCode.of(app)))
      yield Response.json(plans.toJson)
    }

    private def plansByAccountInApp(request: Request): Task[Response] = ensureResponse {
      for
        tk    <- tokenFrom(request)
        req   <- request.body.parse[GetAccountPlansRequest]().mapError(errors.badRequest(s"Error parsing GetAccountPlansRequest"))
        acc   =  if tk.isRoot then req.account else tk.user.details.account
        plans <- repo.exec(FindPlansForAccountInApp(acc, req.application))
      yield Response.json(plans.toJson)
    }.toTask

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
      }.toTask
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

      def ensureUser(identity: CloudIdentity)(maybeUser: Option[RawUser]): Task[RawUser] = {
        maybeUser match
          case Some(user) => ZIO.succeed(user)
          case None       => accounts.provisionSSO(identity)
      }

      ensureResponse {
        for
          vgt       <- request.body.parse[VerifyGoogleTokenRequest]() .mapError(errors.badRequest("Error parsing VerifyGoogleTokenRequest"))
          identity  <- identities.verify(vgt)                         .mapError(GuaraError.of(FirebaseError, s"Error verifying firebase token '${vgt.token}'"))
          fn        =  ensureUser(identity)
          (tk, enc) <- tokenGiven(identity.email) { fn }
        yield loginResponse(tk, enc).clearOriginal
      }.toTask
    }

    private def provision(request: Request): Task[Response] = {

      def ensureIdentifierAvailable(id: AccountIdentifier) = {
        for
          maybe <- repo.exec(FindAccountByIdentifier(id)).mapError(GuaraError.of("Error checking existing identifier"))
          _     <- ZIO.foreach(maybe) { _ => ZIO.logWarning(s"Account '$id' already exists") *> errors.identifierTaken(id) }
        yield ()
      }

      ensureResponse {
        for
          _         <- ZIO.logInfo("Provisioning account")
          req       <- request.body.parse[ProvisionRequest]().mapError(GuaraError.of("bad request"))
          _         <- ensureMagic(req.magic)
          _         <- ZIO.foreach(req.identifier) { ensureIdentifierAvailable }
          maybeUser <- repo.exec(FindUserByEmail(req.email)).mapError(GuaraError.of(UsersError, "Error checking existing user"))
          _         <- ZIO.foreach(maybeUser) { _ => ZIO.logWarning(s"User '${req.email}' already exists") *> errors.emailTaken(req.email) }
          user      <- accounts.provision(req).mapError(GuaraError.of("Error provisioning account"))
          token     <- tokens.asToken(user)   .mapError(GuaraError.of("Error minting the token"))
          encoded   <- tokens.encode(token)   .mapError(GuaraError.of("Error encoding the token"))
          _         <- ZIO.logInfo(s"Account '${req.email}' provisioned")
        yield loginResponse(token, encoded).clearOriginal
      }.toTask
    }

    private def findAccountByIdentifier(request: Request): Task[Response] = {
      ensureResponse {
        for
          req     <- request.body.parse[FindAccountByIdentifierRequest]().mapError(errors.badRequest("Error parsing FindAccountByIdentifierRequest"))
          _       <- ensureMagic(req.magic)
          account <- repo.exec(FindAccountByIdentifier(req.identifier)).mapError(GuaraError.of(AccountNotFound, "Error looking up account by identifier"))
        yield Response.json(account.toJson)
      }.toTask
    }

    private def emitToken(request: Request) = {

      def ensureUser(email: Email)(maybe: Option[RawUser]) = {
        val tuple = for
          user <- maybe
          kind <- user.details.kind
        yield (user, kind)

        tuple match
          case Some(user, UserKind.SA) => ZIO.succeed(user)
          case Some(_, _ )             => GuaraError.fail(UserNotFound, s"Can't find service account: $email")
          case None                    => GuaraError.fail(UserNotFound, s"Can't find user: $email")
      }

      ensureResponse {
        for
          owner    <- tokenFrom(request)
          req      <- request.body.parse[EmitToken]().mapError(errors.badRequest("Error parsing request"))
          _        <- ensureMagic(req.magic)
          (_, enc) <- tokenGiven(req.email, req.days.getOrElse(365), Some(owner)) { ensureUser(req.email) }
          _        <- ZIO.logWarning(s"Service Account Token '${req.email}' created by '${owner.user.details.email}'")
        yield Response.text(enc)
      }.toTask
    }

    private def swapToken(request: Request) = ensureResponse {
      for
        req     <- request.body.parse[SwapTokenRequest]().mapError(errors.badRequest(s"Error parsing swap request"))
        _       <- ensureMagic(req.magic)
        _       <- ZIO.logInfo(s"Swap token request received")
        mlUser  <- legacy.userByToken(req.token).mapError(     GuaraError.of(LegacyUserNotFound, s"Error looking up legacy user by token"))
        user    <- ZIO.fromOption(mlUser)       .mapError(_ => GuaraError.of(LegacyUserNotFound, "Legacy user not found for the given token"))
        _       <- ZIO.logInfo(s"Legacy user found: ${user.email}")
        result  <- tokenGiven(user.email) { maybe => ZIO.fromOption(maybe).mapError(_ => GuaraError.of(UserNotFound, s"User '${user.email}' not found in morbid")) }
        _       <- ZIO.logInfo(s"Token swapped for user '${user.email}'")
      yield Response.text(result._2)
    }.toTask

    private def tokenGiven(email: Email, days: Int = 1, owner: Option[Token] = None)(ensureUser: Option[RawUser] => Task[RawUser]): Task[(Token, String)] = {
      for
        maybeUser <- repo.exec(FindUserByEmail(email)).mapError(GuaraError.of(UserNotFound, s"Error locating user '$email'"))
        user      <- ensureUser(maybeUser)            .mapError(GuaraError.of(UsersError, s"Error ensuring user '$email'"))
        token     <- tokens.asToken(user, days)       .mapError(GuaraError.of(TokenError, s"Error creating token '$email'"))
        result    =  token.copy(impersonatedBy = owner.map(_.user.details))
        encoded   <- tokens.encode(result)            .mapError(GuaraError.of(TokenError, s"Error encoding token '$email'"))
      yield (result, encoded)
    }

    private def loginViaEmailLink(app: String, request: Request): Task[Response] = {
      ensureResponse {
        for {
          req       <- request.body.parse[LoginViaEmailLinkRequest]()
          maybeUser <- repo.exec(FindUserByEmail(req.email))
          _         <- ZIO.fromOption(maybeUser)                         .mapError(_   => GuaraError.of(UserNotFound, s"Can't find user '${req.email}'"))
          link      <- identities.signInWithEmailLink(req.email, req.url).mapError(       GuaraError.of(FirebaseError, s"Error generating login link for '${req.email}'"))
        } yield Response.json(LoginViaEmailLinkResponse(link).toJson)
      }.toTask
    }

    private def logoff(request: Request): Task[Response] = {

      def plainLogoff = ZIO.succeed(Response.json(LogoffResponse(restored = false).toJson).logOff)

      def restore(raw: String): Task[Response] = {
        tokens.verify(raw).foldZIO(
          failure = err => ZIO.logWarning(s"Stashed impersonator token is invalid: ${err.getMessage}") *> plainLogoff,
          success = impersonator =>
            ZIO.logInfo(s"Restoring session for '${impersonator.user.details.email}' after impersonation logout") *>
              ZIO.succeed(Response.json(LogoffResponse(restored = true).toJson).loggedIn(raw).clearOriginal)
        )
      }

      request.cookie(morbid.MorbidCookies.OriginalToken).map(_.content).filter(_.nonEmpty) match
        case Some(raw) => restore(raw)
        case None      => plainLogoff
    }

    private def userBy(request: Request): Task[Response] = {

      val email = request.url.queryParams.get("email").map(Email.of)
      val id    = request.url.queryParams.get("id").map(_.toLong).map(UserId.of)

      def get(cmd: Command[Option[RawUser]]) = {
        for
          user <- repo.exec(cmd).mapError(GuaraError.of(UsersError, s"Error searching for user (id:${id.getOrElse("_")}, email:${email.getOrElse("_")})"))
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

      for
        now     <- Clock.localDateTime
        req     <- request.body.parse[StoreGroupRequest]().mapError(errors.badRequest("Error parsing StoreGroupRequest"))
        app     <- repo.exec(FindApplication(token.user.details.accountCode, application)).orFail(ApplicationNotFound, s"Can't find application '${application}'")
        code    <- req.code.map(ZIO.succeed).getOrElse(uniqueCode)
        _       <- ZIO.logInfo(s"Storing group '${req.name} (${req.id}/$code)' with '${req.users.length}' users, '${req.roles.length}' roles, app '${app.details.code}', account '${token.user.details.account}', tenant '${token.user.details.tenant}'")
        _       <- ZIO.foreach(req.roles) { code => ZIO.logInfo(s"role: $code") }
        _       <- ZIO.foreach(req.users) { code => ZIO.logInfo(s"user: $code") }
        create  =  build(req, app, code, now)
        created <- repo.exec(create)
      yield Response.json(created.toJson)
    }

    private def storeUserCommon(
      request             : Request,
      getAccount          : ()         => Task[RawAccount],
      getApplication      : ()         => Task[RawApplicationDetails],
      validateSameAccount : LegacyUser => Task[Unit]
    ): Task[Response] = {

      def buildRequest(req: StoreUserRequest, account: RawAccount, code: String) =
        req
          .into[StoreUser]
          .withFieldConst(_.id     , req.id.getOrElse(UserId.of(0)))
          .withFieldConst(_.account, account)
          .withFieldConst(_.code   , UserCode.of(code))
          .withFieldConst(_.update , req.update)
          .transform

      def whenNewUser(acc: RawAccount, user: RawUserEntry, application: RawApplicationDetails) = {
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
            case _                                          => GuaraError.fail(GroupNotFound, Status.NotFound, s"Can't find group '${GroupAll}' for application '${application.code}'")
          }
        }

        for
          groups <- repo.exec(FindGroups(acc.code, Seq(application.code), Seq(GroupAll)))
          _      <- link(groups, user).mapError(GuaraError.of(GroupError, "Error adding user to group ALL"))
        yield ()
      }

      def handleFirebaseUser(req: StoreUserRequest, acc: RawAccount, pass: Password) = {
        (req.id, req.update) match
          case (Some(_), false) => identities.createUser(req.email, acc.tenantCode, pass).mapError(GuaraError.of(FirebaseError, "Error storing user identity"))
          case (Some(_), true)  => identities.getUserByEmail(req.email, acc.tenantCode)
          case (None   , _)     => GuaraError.fail(BadRequest, Status.BadRequest, s"User id not provided")
      }

      def handleLegacyMorbid(req: StoreUserRequest, account: RawAccount) = {
        def createWithoutId = legacy.createUser(CreateLegacyUserRequest(account.id, "Provisioned by morbid", req.email, "user")).map(a => req.copy(Some(a.id)))
        def createWithEmail = {
          for
            maybe <- legacy.userByEmail(req.email)
            usr   <- maybe match
              case None       => createWithoutId
              case Some(user) =>
                validateSameAccount(user)
                ZIO.succeed(req.copy(id = Some(user.id)))
          yield usr
        }

        for
          acc <- (req.update, req.id) match
            case (false, _)        => createWithEmail
            case (true , Some(id)) => ZIO.succeed(req)
            case (true , None)     => GuaraError.fail(BadRequest, Status.BadRequest, "Missing parameter 'id'")
        yield acc
      }

      for
        req    <- request.body.parse[StoreUserRequest]().mapError(errors.badRequest("Error parsing StoreUserRequest"))
        acc    <- getAccount()
        app    <- getApplication()
        pass   = Password.of(RandomStringUtils.secure().nextAlphanumeric(10))
        legacy <- handleLegacyMorbid(req, acc)
        fbUser <- handleFirebaseUser(legacy, acc, pass)
        store  = buildRequest(legacy, acc, fbUser.getUid).copy(email = req.email.toLowerCase)
        _      <- ZIO.logInfo(s"Storing user ${store.id} - ${store.email} || Account ${store.account.id} || Tenant ${store.account.tenantCode} || Update: ${store.update}")
        user   <- repo.exec(store).mapError(GuaraError.of(UsersError, s"Error storing user '${store.email}'"))
        _      <- ZIO.logInfo(s"User ${user.id} - ${user.email} stored")
        _      <- ZIO.when(req.id.isEmpty && !req.update) { whenNewUser(acc, user, app) }
      yield Response.json(user.toJson)
    }

    private def storeUser: AppRoute = role("adm" or "user_adm") { request =>
      val token = summon[SingleAppToken]
      val code  = summon[ApplicationCode]
      storeUserCommon(
        request,
        ()   => repo.exec(FindAccountByCode(token.user.details.accountCode)).orFail(AccountNotFound, s"Can't find account '${token.user.details.accountCode}'"),
        ()   => repo.exec(FindApplicationDetails(code)).orFail(ApplicationNotFound, s"Can't find application '$code'"),
        user => ZIO.whenDiscard(user.account.id != token.user.details.account) { GuaraError.fail(s"User already exists in another account || requested by: ${token.user.details.email}") }
      )
    }

    private def removeUserCommon(account: AccountId, code: UserCode) = {
      for
        _ <- repo.exec(RemoveUser(account, code))
      yield ()
    }

    private def removeUser: AppRoute = role("adm" or "user_adm") { request =>

      val token   = summon[SingleAppToken]
      val account = token.user.details.account

      for
        req <- request.body.parse[RemoveUserRequest]().mapError(errors.badRequest("Error parsing RemoveUserRequest"))
        _   <- ZIO.logWarning(s"Removing user '${req.code}'")
        _   <- removeUserCommon(account, req.code)
      yield Response.ok
    }

    private def removeGroup: AppRoute = role("adm" or "group_adm") { request =>

      val token       = summon[SingleAppToken]
      val account     = token.user.details.account
      val application = token.user.application.id

      for
        req    <- request.body.parse[RemoveGroupRequest]().mapError(errors.badRequest("Error parsing RemoveGroupRequest"))
        _      <- ZIO.logWarning(s"Removing group '${req.code}'")
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
    }.toTask

    private def verify(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[VerifyMorbidTokenRequest]().mapError(forbidden)
        token <- tokens.verify(req.token)                      .mapError(forbidden)
      } yield Response.json(token.toJson)
    }.toTask

    private def impersonate(request: Request): Task[Response] = ensureResponse {
      for
        impersonator    <- tokenFrom(request)
        impersonatorRaw <- ZIO.fromOption(rawTokenFrom(request)).mapError(GuaraError.of(Unauthorized, Status.Unauthorized, "Missing impersonator token"))
        req             <- request.body.parse[ImpersonationRequest]()
        _               <- ensureMagic(req.magic)
        user            <- repo.exec(FindUserByEmail(req.email))
        token           <- user match {
                             case Some(usr) => tokens.asToken(usr)
                             case None      => errors.userNotFound(s"user ${req.email} not found")
                           }
        _               <- ZIO.logInfo(s"User '${token.user.details.email}' impersonated by ${impersonator.user.details.email}")
        impersonated    =  token.copy(impersonatedBy = Some(impersonator.user.details))
        encoded         <- tokens.encode(impersonated)
      yield loginResponse(impersonated, encoded).stashOriginal(impersonatorRaw)
    }.toTask

    private def usersGiven(request: Request, application: ApplicationCode, group: Option[GroupCode] = None): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- repo.exec(FindUsersInGroup(tk.user.details.accountCode, application, group))
      } yield Response.json(seq.toJson)
    }.toTask

    private def groupUsers(app: String, group: String, request: Request): Task[Response] = usersGiven(request, ApplicationCode.of(app), Some(GroupCode.of(group)))

    private def groupsByUser(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        req <- request.body.parse[GetUserGroupsRequest]().mapError(errors.badRequest("Error parsing request GetUserGroupsRequest"))
        seq <- repo.exec(FindGroupsByUser(tk.user.details.accountCode, ApplicationCode.of(app), req.user))
      } yield Response.json(seq.toJson)
    }.toTask

    private def setUserGroups(app: String, request: Request): Task[Response] = ensureResponse {
      for
        tk  <- tokenFrom(request)
        req <- request.body.parse[SetUserGroupsRequest]().mapError(errors.badRequest("Error parsing request SetUserGroupsRequest"))
        ok  <- repo.exec(SetUserGroups(tk.user.details.accountCode, ApplicationCode.of(app), req.user, req.groups))
      yield Response.json(ok.toJson)
    }.toTask

    private def groupsGiven(app: String, request: Request): Task[Response] = ensureResponse {
      val appCode = ApplicationCode.of(app)
      for {
        tk     <- tokenFrom(request)
        filter =  request.url.queryParams.getAll("code").map(GroupCode.of)
        map    <- repo.exec(FindGroups(tk.user.details.accountCode, Seq(appCode), filter))
      } yield map.get(appCode) match
        case Some(groups) => Response.json(groups.toJson)
        case None         => Response.notFound(s"Can't find groups for '$app'")
    }.toTask

    private def rolesGiven(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- repo.exec(FindRoles(tk.user.details.accountCode, ApplicationCode.of(app)))
      } yield Response.json(seq.toJson)
    }.toTask

    private def sameUserOr[T <: HasEmail, R](role: Role)(fn: (SingleAppUser, T) => Task[R])(request: Request)(using token: SingleAppToken)(using JsonDecoder[T], JsonEncoder[R]): Task[Response] = (ensureResponse {

      def ifAdmLoadUserSameAccount(token: SingleAppToken, req: T): Task[SingleAppUser] = {

        val application = token.user.application.code
        val isAdm       = role.isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { errors.notAuthorized("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe)                     .mapError(GuaraError.of(UserNotFound, Status.NotFound    , s"Can't find user '${req.email}'"))
          narrowed    <- ZIO.fromOption(user.narrowTo(application)).mapError(GuaraError.of(Unauthorized, Status.Unauthorized, s"User '${req.email}' has no access to application '${application}'"))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { errors.notAuthorized("other account") }
        yield narrowed
      }

      for {
        req    <- request.body.parse[T]()
        me     =  token.user.details.email == req.email
        user   <- if (me) ZIO.succeed(token.user) else ifAdmLoadUserSameAccount(token, req)
        result <- fn(user, req)
      } yield Response.json(result.toJson)
    }).toTask

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
        _ <- ZIO.when(!req.password.isValid) { GuaraError.fail(Forbidden, Status.Forbidden, s"Password for user '$email' is not valid") }
        _ <- identities.changePassword(email, req.password)
      yield true
    }

    private def passwordResetLink: AppRoute = sameUserOr[RequestPasswordRequestLink, PasswordResetLink]("adm" or "user_adm") { (user, req) =>
      for
        _    <- ZIO.logInfo(s"Generating password reset link for '${req.email}'")
        link <- identities.passwordResetLink(req.email).map(PasswordResetLink.apply)
      yield link
    }

    private def setUserPinToBeRemoved(request: Request)(using application: ApplicationCode): Task[Response] = (ensureResponse {

      def changeMyPin(token: Token): Task[UserId] = ZIO.succeed(token.user.details.id)

      def changeSomebodyElse(token: Token, req: SetUserPin): Task[UserId] = {

        val isAdm = ("adm" or "user_adm").isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { errors.notAuthorized("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe).mapError(GuaraError.of(UserNotFound, Status.NotFound, s"Can't find user '${req.email}'"))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { errors.notAuthorized("other account") }
        yield user.details.id
      }

      for {
        req   <- request.body.parse[SetUserPin]()
        token <- tokenFrom(request)
        me    =  token.user.details.email == req.email
        id    <- if (me) changeMyPin(token) else changeSomebodyElse(token, req)
        _     <- pins.set(id, req.pin)
      } yield Response.json(true.toJson)
    }).toTask

    private def passwordResetLinkToBeRemoved(request: Request)(using application: ApplicationCode): Task[Response] = (ensureResponse {

      def changeMyPassword(token: Token, req: RequestPasswordRequestLink): Task[Email] = ZIO.succeed(token.user.details.email)

      def changeSomebodyElse(token: Token, req: RequestPasswordRequestLink): Task[Email] = {

        val isAdm = ("adm" or "user_adm").isSatisfiedBy(token)

        for
          _           <- ZIO.when( !isAdm ) { errors.notAuthorized("not admin") }
          maybe       <- repo.exec(FindUserByEmail(req.email))
          user        <- ZIO.fromOption(maybe).mapError(GuaraError.of(UserNotFound, Status.NotFound, s"Can't find user '${req.email}'"))
          sameAccount = token.user.details.account == user.details.account
          _           <- ZIO.when( !sameAccount ) { errors.notAuthorized("other account") }
        yield req.email
      }

      for
        token <- tokenFrom(request)
        req   <- request.body.parse[RequestPasswordRequestLink]().mapError(errors.badRequest("Error parsing RequestPasswordRequestLink"))
        me    =  token.user.details.email == req.email
        email <- if (me) changeMyPassword(token, req) else changeSomebodyElse(token, req)
        link  <- identities.passwordResetLink(email)
      yield Response.json(PasswordResetLink(link).toJson)

    }).toTask

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

      for
        req     <- request.body.parse[CreateAccount]()
        _       <- ZIO.logInfo(s"Account Provisioning '${req.email}'")
        maybe   <- repo.exec(FindApplicationDetails(Presto))
        details <- ZIO.fromOption(maybe).mapError(GuaraError.of(ApplicationNotFound, s"Can't find application '$Presto'"))
        acc     <- repo.exec {
          req
            .into[StoreAccount]
            .withFieldConst(_.active, true)
            .withFieldConst(_.update, false)
            .transform
        }
        app     =  RawApplication(details)
        _       <- repo.exec(LinkAccountToApp(acc.id,  app.details.id))
        now     <- Clock.localDateTime
        groups  <- createGroups(now, app, acc)
        admin   <- ZIO.fromOption(groups.find(_.code == GroupCode.admin).map(_.id)).mapError(GuaraError.of(GroupError, "Can't find group 'admin' after account creation"))
        all     <- ZIO.fromOption(groups.find(_.code == GroupCode.all)  .map(_.id)).mapError(GuaraError.of(GroupError, "Can't find group 'all' after account creation"))
        fbUser  <- identities.createUser(req.email, acc.tenantCode, Password.of(RandomStringUtils.secure().nextAlphanumeric(10)))
        store   = StoreUser(id = req.user, email = req.email.toLowerCase, code = UserCode.of(fbUser.getUid), account = acc, kind = None, update = false, active = true)
        user    <- repo.exec(store)
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = admin, users = Seq(user.id)))
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = all  , users = Seq(user.id)))
        created <- repo.exec(FindUserById(user.id))
      yield created match
        case None        => Response.internalServerError(s"Error provisioning account ${req.email}")
        case Some(value) => Response.json(value.toJson)
    }

    private def provisionUsers: AppRoute = role("adm") { request =>

      val appCode = summon[ApplicationCode]

      for
        form    <- request.body.asMultipartForm
        code    <- ZIO.fromOption(form.get("account")).mapError(GuaraError.of(BadRequest, Status.BadRequest, "No field called 'account'"))
        file    <- ZIO.fromOption(form.get("file"))   .mapError(GuaraError.of(BadRequest, Status.BadRequest, "No field called 'file'"))
        value   <- code.asText
        text    <- file.asText
        acc     <- repo.get(FindAccountByCode(AccountCode.of(value))) { s"Can't find account '$value'" }
        app     <- repo.get(FindApplicationDetails(appCode))          { s"Can't find application '$appCode' "}
        groups  <- repo.exec(FindGroups(account = acc.code, apps = Seq(appCode)))
        group   <- ZIO.fromOption(groups.get(appCode).flatMap(_.find(_.code == GroupCode.all))).mapError(GuaraError.of(GroupNotFound, s"Can't find group '${GroupCode.all}' in account '${acc.id}'"))
        entries <- accounts.parseCSV(acc, text)
        created =  entries.map(_._2).filter(_.isSuccess).map(_.get).map(_.id)
        _       <- repo.exec(LinkUsersToGroup(app.id, group.id, created))
      yield Response.json {
        entries.map {
          case (email, Success(user)) => (Email.value(email), s"[ok] ${user.id}")
          case (email, Failure(err))  => (Email.value(email), s"[err] ${err.getMessage}")
        }.toMap.toJson
      }
    }

    private def entitiesByValidate[R](validateToken: ValidateToken)(request: Request, command: Command[R])(using JsonCodec[R]) = ensureResponse {
      for
        _   <- validateToken(request)
        tk  <- tokenFrom(request)
        _   <- ZIO.logInfo(s"Executing 'EntitiesByValidate' | Requested by: ${tk.user.details.email} | Command: ${command.getClass.toString}")
        res <- repo.exec(command)
      yield Response.json(res.toJson)
    }.toTask

    private def accountsByApp(validateToken: ValidateToken)(app: String, request: Request) = {
      entitiesByValidate(validateToken)(request, FindAccountsByApp(ApplicationCode.of(app)))
    }

    private def usersByApp(validateToken: ValidateToken)(app: String, request: Request) = {
      entitiesByValidate(validateToken)(request, FindUsersByApp(ApplicationCode.of(app)))
    }

    private def managerGetUsers(app: String, acc: Long, request: Request) = {
      entitiesByValidate(requireRootAccount)(request, UsersByAccount(ApplicationCode.of(app), AccountId.of(acc)))
    }

    private def storeAccount(app: String, request: Request) = {

      def createGroups(now: LocalDateTime, app: RawApplication, acc: RawAccount) = {

        val groups = Seq(
          RawGroup(id = GroupId.of(0), created = now, deleted = None, code = GroupCode.all, name = GroupName.of("Todos"), roles = Seq.empty),
          RawGroup(id = GroupId.of(0), created = now, deleted = None, code = GroupCode.admin, name = GroupName.of("Admin"), roles = Seq.empty)
        )

        val commands = groups.map { group =>
          val roles = if (group.code == GroupCode.admin) Seq(RoleCode.of("adm")) else Seq.empty
          StoreGroup(account = acc.id, accountCode = acc.code, application = app, group = group, users = Seq.empty, roles = roles)
        }

        for
          grps  <- ZIO.foreach(commands) { repo.exec }
          admin <- ZIO.fromOption(grps.find(_.code == GroupCode.admin).map(_.id)).mapError(GuaraError.of(GroupNotFound, "Can't find group 'admin' after account creation"))
          all   <- ZIO.fromOption(grps.find(_.code == GroupCode.all).map(_.id))  .mapError(GuaraError.of(GroupNotFound, "Can't find group 'all' after account creation"))
        yield ()
      }

      def handleLegacyMorbid(req: StoreAccountRequest) = {

        def createWithoutId = legacy.createAccount(CreateLegacyAccountRequest(req.name, "regular")).map(a => req.copy(Some(a.id)))

        def createWithId(id: AccountId) = {
          for
            maybe <- legacy.accountById(id)
            acc   <- maybe match
              case Some(acc) => ZIO.succeed(req.copy(id = Some(acc.id)))
              case None      => createWithoutId
          yield acc
        }
        
        for
          acc <- (req.update, req.id) match
            case (false, Some(id)) => createWithId(id)
            case (false, None)     => createWithoutId // TODO Verificar, se não validarmos corretamente, vai ocasionar contas duplicadas, caso a conta já exista no console4 e o usuário não tenha passado o id da conta no Presto por ex
            case (true , Some(id)) => ZIO.succeed(req) // Legacy morbid does not update accounts
            case (true , None)     => GuaraError.fail(BadRequest, Status.BadRequest, "Missing parameter 'id'")
        yield acc
      }

      def buildEntity(req: StoreAccountRequest) = {
        req
          .into[StoreAccount]
          .withFieldConst(_.id, req.id.getOrElse(AccountId.of(0)))
          .transform
      }

      def afterInsert(details: RawApplicationDetails, account: RawAccount, req: StoreAccountRequest) = {
        val app = RawApplication(details)
        for
          _   <- repo.exec(LinkAccountToApp(account.id, app.details.id))
          now <- Clock.localDateTime
          _   <- ZIO.when(req.update) { createGroups(now, app, account) }
        yield ()
      }

      for
        tk      <- tokenFrom(request)
        _       <- requireRootAccount(request)
        req     <- request.body.parse[StoreAccountRequest]()
        _       <- ZIO.logInfo(s"Store account ${req.id} - ${req.name} || Requested by: ${tk.user.details.email}")
        legacy  <- handleLegacyMorbid(req)
        code    = ApplicationCode.of(app)
        maybe   <- repo.exec(FindApplicationDetails(code))
        details <- ZIO.fromOption(maybe).mapError(GuaraError.of(ApplicationNotFound, s"Can't find application '$code'"))
        acc     <- repo.exec(buildEntity(legacy))
        _       <- ZIO.unless(req.update) { afterInsert(details, acc, req) }
      yield Response.json(acc.toJson)
    }

    private def removeAccount(app: String, acc: Long, request: Request) = {
      for
        tk <- tokenFrom(request)
        _  <- requireRootAccount(request)
        _  <- ZIO.logInfo(s"Delete account $acc || Requested by: ${tk.user.details.email}")
        _  <- repo.exec(RemoveAccount(AccountId.of(acc)))
      yield Response.json(true.toJson)
    }

    private def managerStoreUser(app: String, acc: Long, request: Request) = {
      for
        _        <- requireRootAccount(request)
        response <- storeUserCommon(
          request,
          ()   => repo.exec(FindAccountById(AccountId.of(acc))).orFail(AccountNotFound, s"Can't find account '$acc'"),
          ()   => repo.exec(FindApplicationDetails(ApplicationCode.of(app))).orFail(ApplicationNotFound, s"Can't find application '$app'"),
          user => ZIO.unit
        )
      yield response
    }

    private def managerRemoveUser(app: String, acc: Long, code: String, request: Request) = {
      for
        tk <- tokenFrom(request)
        _  <- requireRootAccount(request)
        _  <- ZIO.logInfo(s"Delete user $code || Requested by: ${tk.user.details.email}")
        _  <- removeUserCommon(AccountId.of(acc), UserCode.of(code))
      yield Response.json(true.toJson)
    }

    private def requireRootAccount(request: Request) = {
      for
        tk <- tokenFrom(request)
        _  <- ZIO.unless(tk.user.details.account == RootAccount) { errors.notAuthorized("Operation required root account") }
      yield ()
    }

    private def managerRoutes = Routes(
      Method.POST   / "app" / string("app") / "manager/account"                                         -> handler(storeAccount),
      Method.DELETE / "app" / string("app") / "manager/account" / long("acc")                           -> handler(removeAccount),
      Method.GET    / "app" / string("app") / "manager/accounts"                                        -> handler(accountsByApp(requireRootAccount)),
      Method.POST   / "app" / string("app") / "manager/account" / long("acc") / "user"                  -> handler(managerStoreUser),
      Method.DELETE / "app" / string("app") / "manager/account" / long("acc") / "user" / string("code") -> handler(managerRemoveUser),
      Method.GET    / "app" / string("app") / "manager/account" / long("acc") / "users"                 -> handler(managerGetUsers),
    ).sandbox

    private def serviceRoutes = Routes(
      Method.GET / "service" / "app" / string("app") /"users"    -> handler(usersByApp(testServiceToken)),
      Method.GET / "service" / "app" / string("app") /"accounts" -> handler(accountsByApp(testServiceToken)),
    ).sandbox

    private def regular = Routes(
      Method.GET  / "applications"                                               -> Handler.fromFunctionZIO[Request](applicationDetailsGiven),
      Method.GET  / "application" / string("app")                                -> handler(applicationGiven),
      Method.GET  / "application" / string("app") / "plans"                      -> handler(plansByApp),
      Method.POST / "account" / "plans"                                          -> Handler.fromFunctionZIO[Request](plansByAccountInApp),
      Method.POST / "login" / "provider"                                         -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.GET  / "login" / "provider"                                         -> Handler.fromFunctionZIO[Request](loginProviderForAccount),
      Method.POST / "login"                                                      -> Handler.fromFunctionZIO[Request](login),
      Method.POST / "provision"                                                  -> Handler.fromFunctionZIO[Request](provision),
      Method.POST / "account" / "by-identifier"                                  -> Handler.fromFunctionZIO[Request](findAccountByIdentifier),
      Method.POST / "logoff"                                                     -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST / "verify"                                                     -> Handler.fromFunctionZIO[Request](verify),
      Method.POST / "impersonate"                                                -> Handler.fromFunctionZIO[Request](impersonate),
      Method.POST / "emit"                                                       -> Handler.fromFunctionZIO[Request](emitToken),
      Method.POST / "swap"                                                       -> Handler.fromFunctionZIO[Request](swapToken),
      Method.GET  / "user"                                                       -> Handler.fromFunctionZIO[Request](userBy),
      Method.POST / "user" / "pin" / "validate"                                  -> Handler.fromFunctionZIO[Request](validateUserPin),
      Method.POST / "app" / string("app") / "login" / "email"                    -> handler(loginViaEmailLink),
      Method.POST / "app" / string("app") / "user" / "pin"                       -> handler(protect(setUserPin)),
      Method.POST / "app" / string("app") / "password" / "reset"                 -> handler(protect(passwordResetLink)),
      Method.POST / "app" / string("app") / "password" / "change"                -> handler(protect(changePassword)),
      Method.GET  / "app" / string("app") / "users"                              -> handler(protect(usersGiven)),
      Method.POST / "app" / string("app") / "user"                               -> handler(protect(storeUser)),
      Method.POST / "app" / string("app") / "user"  / "delete"                   -> handler(protect(removeUser)),
      Method.GET  / "app" / string("app") / "groups"                             -> handler(groupsGiven),
      Method.POST / "app" / string("app") / "group"                              -> handler(protect(storeGroup)),
      Method.POST / "app" / string("app") / "group" / "delete"                   -> handler(protect(removeGroup)),
      Method.GET  / "app" / string("app") / "group"  / string("code") / "users"  -> handler(groupUsers),
      Method.POST / "app" / string("app") / "user"           / "groups" / "find" -> handler(groupsByUser),
      Method.POST / "app" / string("app") / "user"                     / "groups"-> handler(setUserGroups),
      Method.GET  / "app" / string("app") / "roles"                              -> handler(rolesGiven),
      Method.POST / "app" / string("app") / "account"                            -> handler(protect(provisionAccount)),
      Method.POST / "app" / string("app") / "account" / "users"                  -> handler(protect(provisionUsers))
    ).sandbox

    override def routes = Echo.routes ++ managerRoutes ++ regular ++ serviceRoutes @@ cors(corsConfig)
  }
}