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
import guara.utils.parse
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

  case class MorbidRouter(cfg: MorbidConfig, identities: Identities, accounts: AccountManager, tokens: TokenGenerator) extends Router {

    private def loginProvider(request: Request): Task[Response] = {

      def encode(provider: Option[RawIdentityProvider]): String = {
        provider match
          case None                                                                     => s"""{"type": "up"}"""
          case Some(RawIdentityProvider(_, _, _, _, _, _, ProviderKind.UP  , _, _))     => s"""{"type": "up"}"""
          case Some(RawIdentityProvider(_, _, _, _, _, _, ProviderKind.SAML, id, name)) => s"""{"type": "saml", "id": "$id", "name": "$name"}"""
      }

      GuaraError.trap {
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

      GuaraError.trap {
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

    private def verify(request: Request): Task[Response] = {
      GuaraError.trap {
        for {
          req   <- request.body.parse[VerifyMorbidTokenRequest]
          token <- tokens.verify(req.token)
        } yield Response.json(token.toJson)
      }
    }

    private def impersonate(request: Request): Task[Response] = {
      GuaraError.trap {
        for {
          req   <- request.body.parse[ImpersonationRequest]
          same  =  req.magic.is(cfg.magic.password)
          _     <- ZIO.when(!same) { ZIO.fail(new Exception("Bad Magic")) }
        } yield Response.notImplemented
      }
    }

    private def regular = Routes(
      Method.POST / "login" / "provider" -> Handler.fromFunctionZIO[Request](loginProvider),
      Method.POST / "login"              -> Handler.fromFunctionZIO[Request](login),
      Method.POST / "logoff"             -> Handler.fromFunctionZIO[Request](logoff),
      Method.POST / "verify"             -> Handler.fromFunctionZIO[Request](verify),
      Method.POST / "impersonate"        -> Handler.fromFunctionZIO[Request](impersonate),
      Method.GET  / "test"               -> Handler.fromFunctionZIO[Request](test),
      Method.GET  / "user"               -> Handler.fromFunctionZIO[Request](userByEmail),
    ).sandbox.toHttpApp

    override def routes: HttpApp[Any] = Echo.routes ++ regular @@ cors(corsConfig)
  }
}