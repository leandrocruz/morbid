package morbid.admin.api

import ApiError.{forbidden, unauthorized}
import morbid.domain.RootAccount
import morbid.domain.token.{RawToken, Token}
import morbid.types.AccountId
import zio.*
import zio.http.*
import zio.http.Cookie.SameSite

/** The outcome of authenticating the admin-session cookie: the raw Morbid token (to
  * forward to Morbid) alongside the parsed/verified token. Only root-account users
  * reach this point — the account check happens up-front at login time and again on
  * each request, so the handlers can assume the caller is an admin.
  */
case class AdminSession(raw: RawToken, token: Token) {
  def account = token.user.details.account
  def email   = token.user.details.email
}

trait AdminAuth {
  def authenticate (header: Option[AuthorizationHeader], cookie: Option[String]) : IO[ApiError, AdminSession]
  def requireRoot  (session: AdminSession)                                       : IO[ApiError, Unit]
  def login        (firebaseToken: String)                                       : IO[ApiError, (AdminSession, Cookie.Response)]
  def logoutCookie                                                               : Cookie.Response
  def cookieFor    (rawToken: String)                                            : Cookie.Response
}

object AdminAuth {
  val layer: ZLayer[AppConfig & MorbidGateway, Nothing, AdminAuth] =
    ZLayer.fromFunction { (cfg: AppConfig, gw: MorbidGateway) =>
      MorbidAdminAuth(cfg, gw): AdminAuth
    }
}

type AuthorizationHeader = AuthorizationHeader.Type
object AuthorizationHeader extends neotype.Newtype[String]

case class MorbidAdminAuth(cfg: AppConfig, gw: MorbidGateway) extends AdminAuth {

  override def cookieFor(rawToken: String): Cookie.Response = Cookie.Response(
    name       = cfg.cookie.name,
    content    = rawToken,
    domain     = cfg.cookie.domain,
    maxAge     = Some(1.days),
    isHttpOnly = true,
    isSecure   = cfg.cookie.secure,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  override def logoutCookie: Cookie.Response = Cookie.Response(
    name       = cfg.cookie.name,
    content    = "",
    domain     = cfg.cookie.domain,
    maxAge     = Some(0.seconds),
    isHttpOnly = true,
    isSecure   = cfg.cookie.secure,
    sameSite   = Some(SameSite.Lax),
    path       = Some(Path("/"))
  )

  private def tokenFromHeader(header: Option[AuthorizationHeader]): Option[String] =
    header.map(AuthorizationHeader.unwrap).map(_.trim).collect {
      case s if s.startsWith("Bearer ") => s.drop(7).trim
    }.filter(_.nonEmpty)

  override def authenticate(header: Option[AuthorizationHeader], cookie: Option[String]): IO[ApiError, AdminSession] = {
    val raw = tokenFromHeader(header).orElse(cookie).filter(_.nonEmpty)
    for
      value   <- ZIO.fromOption(raw).orElseFail(unauthorized("Missing authentication"))
      rawTk    = RawToken.of(value)
      token   <- gw.verify(rawTk).mapError(err => unauthorized(s"Invalid token: ${err.getMessage}"))
      session  = AdminSession(rawTk, token)
      _       <- requireRoot(session)
    yield session
  }

  override def requireRoot(session: AdminSession): IO[ApiError, Unit] =
    ZIO.unless(session.account == RootAccount) {
      ZIO.fail(forbidden(s"Only root-account users can use the admin console"))
    }.unit

  override def login(firebaseToken: String): IO[ApiError, (AdminSession, Cookie.Response)] = {
    for
      pair         <- gw.loginWithFirebase(firebaseToken).mapError {
                        case guara.errors.ReturnResponseError(res) if res.status.code == 401 || res.status.code == 403 =>
                          unauthorized("Login refused by Morbid")
                        case err =>
                          ApiError.from(err)
                      }
      (token, raw)  = pair
      session       = AdminSession(RawToken.of(raw), token)
      _            <- requireRoot(session)
    yield (session, cookieFor(raw))
  }
}
