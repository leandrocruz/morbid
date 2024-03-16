package morbid

import types.*
import config.MorbidConfig
import billing.Billing
import domain.*
import domain.raw.*
import domain.simple.*
import domain.mini.*
import tokens.*
import proto.*
import utils.asJson
import guara.utils.{ensureResponse, parse}
import guara.domain.RequestId
import guara.errors.*
import guara.router.Router
import guara.router.Echo
import morbid.accounts.AccountManager
import morbid.gip.*
import morbid.repo.Repo
import zio.*
import zio.http.Cookie.SameSite
import zio.json.*
import zio.http.{Cookie, Handler, Header, HttpApp, Method, Path, Request, Response, Routes, handler}
import zio.http.Middleware.CorsConfig
import zio.http.Middleware.{CorsConfig, cors}
import zio.http.Status
import zio.http.Header.{AccessControlAllowMethods, AccessControlAllowOrigin, Origin}
import zio.http.codec.PathCodec.{long, string}
import zio.json.ast.{Json, JsonCursor}
import zio.logging.LogFormat
import zio.logging.backend.SLF4J
import io.scalaland.chimney.dsl.*
import morbid.applications.Applications
import morbid.domain.token.Token
import morbid.groups.GroupManager
import morbid.passwords.PasswordGenerator
import morbid.roles.RoleManager
import morbid.pins.PinManager

import scala.util.Random
import java.time.{Instant, LocalDateTime}
import java.util.Base64

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

  private val corsConfig =  CorsConfig()

  object MorbidRouter {
    val layer = ZLayer.fromFunction(MorbidRouter.apply _)
  }

  case class LoginSuccess(email: String, admin: Boolean)

  case class MorbidRouter(
    accounts     : AccountManager,
    applications : Applications,
    billing      : Billing,
    cfg          : MorbidConfig,
    groups       : GroupManager,
    identities   : Identities,
    pins         : PinManager,
    passGen      : PasswordGenerator,
    roles        : RoleManager,
    tokens       : TokenGenerator
  ) extends Router {

    private given ApplicationCode = utils.Morbid

    private def tokenFrom(request: Request): Task[Token] = {
      (request.headers.get("X-MorbidToken"), request.cookie("morbid-token")) match
        case (None, None     ) => GuaraError.fail(Response.unauthorized("Authorization cookie or header is missing"))
        case (Some(header), _) => tokens.verify(header)
        case (_, Some(cookie)) => tokens.verify(cookie.content)
    }

    private def applicationDetailsGiven(request: Request): Task[Response] = {
      for {
        tk   <- tokenFrom(request)
        apps <- applications.applicationDetailsGiven(tk.user.details.accountCode)
      } yield Response.json(apps.toJson)
    }

    private def applicationGiven(app: String, request: Request): Task[Response] = {
      for {
        tk     <- tokenFrom(request)
        result <- applications.applicationGiven(tk.user.details.accountCode, ApplicationCode.of(app))
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
        domain <- ZIO.fromOption(token.user.details.email.domainName).mapError(_ => new Exception("Error extracting domain from user email"))
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
          maybeUser <- accounts.userByEmail(identity.email)
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

    private def test(request: Request): Task[Response] = {
      ZIO.succeed {
        request.cookie("morbid-token") match
          case Some(value) => Response.ok
          case None        => Response.forbidden
      }
    }

    private def userByEmail(request: Request): Task[Response] = {
      for {
        email     <- ZIO.fromOption(request.url.queryParams.get("email")).mapError(_ => new Exception("email not provided"))
        maybeUser <- accounts.userByEmail(Email.of(email))
      } yield maybeUser match
        case None       => Response.notFound
        case Some(user) => Response.json(user.asJson(request.url.queryParams.get("format")))
    }

    private def role(code: String, codes: String*)(fn: (Request, Token) => Task[Response])(request: Request): Task[Response] = {

      def hasRole(token: Token)(role: RoleCode): Task[RawRole] = {

        ZIO
          .fromOption(token.roleByCode(role))
          .mapError(_ => ReturnResponseError(Response.forbidden(s"Required role $role is missing")))
      }

      val roles = codes.toList.prepended(code).map(name => RoleCode.of(name))
      ensureResponse {
        for {
          token  <- tokenFrom(request).debug
          _      <- ZIO.foreach(roles) { hasRole(token) }
          result <- fn(request, token)
        } yield result
      }
    }

    private def createUser = role("user_adm") { (request, token) =>

      def configureApplications(user: RawUser, req: CreateUserRequest): Task[Seq[Unit]] = {

        def configureApplication(cua: CreateUserApplication): Task[Unit] = {

          def ensureApplication(app: Option[RawApplication]): Task[RawApplication] = {
            ZIO.fromOption(app).mapError(_ => new Exception(s"Can't find application '${cua.application}' for account '${user.details.accountCode}'"))
          }

          def ensureGroups(application: RawApplication): Task[Seq[RawGroup]] = {
            val found = cua.groups.map(code => (code, application.groups.find(_.code == code)))
            ZIO.foreach(found) {
              case (code, None      ) => ZIO.fail(new Exception(s"Group '$code' is missing in application '${application.details.code}' for account '${user.details.accountCode}'"))
              case (_   , Some(item)) => ZIO.succeed(item)
            }
          }

          def ensureRoles(application: RawApplication): Task[Seq[RawRole]] = {
            val found = cua.roles.map(code => (code, application.roles.find(_.code == code)))
            ZIO.foreach(found) {
              case (code, None)       => ZIO.fail(new Exception(s"Role '$code' is missing in application '${application.details.code}' for account '${user.details.accountCode}'"))
              case (_   , Some(item)) => ZIO.succeed(item)
            }
          }

          for {
            maybe       <- applications.applicationGiven(user.details.accountCode, cua.application)
            application <- ensureApplication(maybe)
            groupsToAdd <- ensureGroups(application)
            rolesToAdd  <- ensureRoles(application)
            _           <- groups .addGroups(user.details.account, application.details.id, user.details.id, groupsToAdd.map(_.id)) .fork
            _           <- roles  .addRoles (user.details.account, application.details.id, user.details.id, rolesToAdd.map(_.id))  .fork
          } yield ()
        }

        ZIO.foreachPar(req.applications) {
          configureApplication
        }
      }

      def uniqueCode(email: Email): Task[UserCode] = {

        def attemptUnique(user: EmailUser, count: Int): Task[UserCode] = {

          def gen: Task[UserCode] = ZIO.attempt(UserCode.of(Random.alphanumeric.take(128).mkString("")))

          for {
            _      <- ZIO.when(count > 10) { ZIO.fail(new Exception("Can't generate user code. Too many attempts")) }
            tmp    <- gen
            exists <- accounts.userExists(tmp)
            code   <- if(exists) attemptUnique(user, count + 1) else ZIO.succeed(tmp)
          } yield code
        }

        email.userName match
          case None       => ZIO.fail(new Exception(s"Error generating code from '$email'"))
          case Some(user) => attemptUnique(user, 0)
      }

      def buildRequest(req: CreateUserRequest, token: Token, password: Password, code: UserCode) =
        req
          .into[CreateUser]
          .withFieldConst(_.account, token.user.details.accountCode)
          .withFieldConst(_.password, password)
          .withFieldConst(_.code, code)
          .transform

      for
        req    <- request.body.parse[CreateUserRequest]
        pwd    <- ZIO.fromOption(req.password) .orElse(passGen.generate)
        code   <- ZIO.fromOption(req.code)     .orElse(uniqueCode(req.email))
        create  = buildRequest(req, token, pwd, code)
        _      <- ZIO.logInfo(s"Creating user '${create.email}' in account '${create.account}' in tenant '${create.tenant.getOrElse("_")}'")
        user   <- accounts.createUser(create)
        _      <- ZIO.logInfo(s"User '${user.details.email}' created. Configuring applications: ${req.applications.map(_.application).mkString(", ")}")
        _      <- configureApplications(user, req) <&> identities.createUser(create)
        _      <- ZIO.logInfo(s"Creation for user '${create.email}' successful")
      yield Response.json(user.toJson)
    }

    private def setUserPin(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[SetUserPin]
        token <- tokenFrom(request)
        _     <- pins.set(token.user.details.id, req.pin)
      } yield Response.ok
    }

    private def validateUserPin(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[SetUserPin]
        token <- tokenFrom(request)
        valid <- pins.validate(token.user.details.id, req.pin)
      } yield if(valid) Response.ok else Response.forbidden
    }

    private def verify(request: Request): Task[Response] = ensureResponse {
      for {
        req   <- request.body.parse[VerifyMorbidTokenRequest]
        token <- tokens.verify(req.token)
      } yield Response.json(token.toJson)
    }

    private def impersonate(request: Request): Task[Response] = ensureResponse {
      for {
        req     <- request.body.parse[ImpersonationRequest]
        same    =  req.magic.is(cfg.magic.password)
        _       <- ZIO.when(!same) { ZIO.fail(new Exception("Bad Magic")) }
        user    <- accounts.userByEmail(req.email)
        token   <- user match {
                  case Some(usr) => tokens.asToken(usr)
                  case None      => ZIO.fail(ReturnResponseError(Response.notFound(s"user ${req.email} not found")))
                }
        encoded <- tokens.encode(token)
      } yield loginResponse(token, encoded)
    }

    private def userCount(app: String, request: Request): Task[Response] = {
      role("adm") { (_, _) =>
        for {
          data   <- billing.usersByAccount(ApplicationCode.of(app))
          result = data.map {
                     case (acc, count) => (s"${acc.name} (id:${acc.id}, code:${acc.code})", count)
                   }
        } yield Response.json(result.toJson)
      } (request)
    }

    private def usersGiven(request: Request, application: ApplicationCode, group: Option[GroupCode] = None): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- groups.usersFor(tk.user.details.accountCode, application, group)
      } yield Response.json(seq.toJson)
    }

    private def usersGiven(app: String, request: Request)                : Task[Response] = usersGiven(request, ApplicationCode.of(app))
    private def groupUsers(app: String, group: String, request: Request) : Task[Response] = usersGiven(request, ApplicationCode.of(app), Some(GroupCode.of(group)))

    private def groupsGiven(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk     <- tokenFrom(request)
        filter =  request.url.queryParams.getAll("code").getOrElse(Seq.empty).map(GroupCode.of)
        seq    <- groups.groupsFor(tk.user.details.accountCode, ApplicationCode.of(app), filter)
      } yield Response.json(seq.toJson)
    }

    private def rolesGiven(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- roles.rolesFor(tk.user.details.accountCode, ApplicationCode.of(app))
      } yield Response.json(seq.toJson)
    }

    private def regular = Routes(
      Method.GET  / "applications"                   -> Handler.fromFunctionZIO[Request](applicationDetailsGiven),
      Method.GET  / "application" / string("app")    -> handler(applicationGiven),
      Method.POST / "login" / "provider"             -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.GET  / "login" / "provider"             -> Handler.fromFunctionZIO[Request](loginProviderForAccount),
      Method.POST / "login"                          -> Handler.fromFunctionZIO[Request](login),
      Method.POST / "logoff"                         -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST / "verify"                         -> Handler.fromFunctionZIO[Request](verify),
      Method.POST / "impersonate"                    -> Handler.fromFunctionZIO[Request](impersonate),
      Method.GET  / "test"                           -> Handler.fromFunctionZIO[Request](test),
      Method.GET  / "user"                           -> Handler.fromFunctionZIO[Request](userByEmail),
      Method.POST / "user"                           -> Handler.fromFunctionZIO[Request](createUser),
      Method.POST / "user" / "pin"                   -> Handler.fromFunctionZIO[Request](setUserPin),
      Method.POST / "user" / "pin" / "validate"      -> Handler.fromFunctionZIO[Request](validateUserPin),
      Method.GET  / "app" / string("app") / "users"  -> handler(usersGiven),
      Method.GET  / "app" / string("app") / "groups" -> handler(groupsGiven),
      Method.GET  / "app" / string("app") / "group"  / string("code") / "users" -> handler(groupUsers),
      Method.GET  / "app" / string("app") / "roles" -> handler(rolesGiven),
    ).sandbox.toHttpApp

    override def routes: HttpApp[Any] = Echo.routes ++ regular @@ cors(corsConfig)
  }
}