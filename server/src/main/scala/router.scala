package morbid

import types.*
import config.MorbidConfig
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
import morbid.domain.token.Token
import morbid.groups.GroupManager
import morbid.pins.PinManager

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

  case class MorbidRouter(cfg: MorbidConfig, identities: Identities, accounts: AccountManager, groups: GroupManager, tokens: TokenGenerator, pins: PinManager) extends Router {

    private given ApplicationCode = utils.Morbid

    private def tokenFrom(request: Request): Task[Token] = {
      request.headers.get("X-MorbidToken") match
        case None        => GuaraError.fail(Response.unauthorized("Authorization cookie or header is missing"))
        case Some(value) => tokens.verify(value)
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

    private def login(request: Request): Task[Response] = {

      def ensureUser(identity: CloudIdentity, maybeUser: Option[RawUser]): Task[RawUser] = {
        maybeUser match {
          case Some(user) => ZIO.succeed(user)
          case None       => accounts.provision(identity)
        }
      }

      ensureResponse {
        for {
          token     <- request.body.parse[VerifyGoogleTokenRequest]
          identity  <- identities.verify(token)
          maybeUser <- accounts.userByEmail(identity.email)
          user      <- ensureUser(identity, maybeUser)
          encoded   <- tokens.encode(user)
        } yield Response.ok.loggedIn(encoded)
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
        maybeUser <- accounts.userByEmail(email.as[Email])
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

      val roles = codes.toList.prepended(code).map(RoleCode.of)
      ensureResponse {
        for {
          token  <- tokenFrom(request)
          _      <- ZIO.foreach(roles) { hasRole(token) }
          result <- fn(request, token)
        } yield result
      }
    }

    private def createUser = role("user_adm") { (request, token) =>

      def securePassword = Password.of("xixicoco") //TODO
      def userCode       = UserCode.of("zzz") //TODO

      for {
        req    <- request.body.parse[CreateUserRequest].debug
        pwd    = req.password.getOrElse(securePassword)
        code   = req.code.getOrElse(userCode)
        create = req.into[CreateUser].withFieldConst(_.account, token.user.details.accountCode).withFieldConst(_.password, pwd).withFieldConst(_.code, code).transform
        user   <- accounts.createUser(create)
        _      <- identities.createUser(create)
      } yield Response.json(user.toJson) //TODO: return password
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
        encoded <- user match {
                  case Some(value) => tokens.encode(value)
                  case None        => ZIO.fail(ReturnResponseError(Response.notFound(s"user ${req.email} not found")))
                }
      } yield Response.json(user.toJson).loggedIn(encoded)
    }

    private def groupsGiven(app: String, request: Request): Task[Response] = ensureResponse {
      for {
        tk  <- tokenFrom(request)
        seq <- groups.groupsFor(tk.user.details.account, app.as[ApplicationCode])
      } yield Response.json(seq.toJson)
    }

    private def regular = Routes(
      Method.POST / "login" / "provider"        -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.POST / "login"                     -> Handler.fromFunctionZIO[Request](login),
      Method.POST / "logoff"                    -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST / "verify"                    -> Handler.fromFunctionZIO[Request](verify),
      Method.POST / "impersonate"               -> Handler.fromFunctionZIO[Request](impersonate),
      Method.GET  / "test"                      -> Handler.fromFunctionZIO[Request](test),
      Method.GET  / "user"                      -> Handler.fromFunctionZIO[Request](userByEmail),
      Method.POST / "user"                      -> Handler.fromFunctionZIO[Request](createUser),
      Method.POST / "user" / "pin"              -> Handler.fromFunctionZIO[Request](setUserPin),
      Method.POST / "user" / "pin" / "validate" -> Handler.fromFunctionZIO[Request](validateUserPin),
      Method.GET  / "groups" / string("app")    -> handler(groupsGiven),
    ).sandbox.toHttpApp

    override def routes: HttpApp[Any] = Echo.routes ++ regular @@ cors(corsConfig)
  }
}