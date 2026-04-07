package morbid.cookies

import guara.http.errors.*
import guara.framework.router.{Echo, Router}
import guara.http.{Origin, SafeResponse, ensureResponse}
import guara.http.SafeResponse.*
import guara.http.extensions.parse
import io.scalaland.chimney.dsl.*
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

val auth = Cookie.Response(
  name       = "morbid-auth",
  content    = "true",
  maxAge     = Some(1.days),
  isHttpOnly = false,
  sameSite   = Some(SameSite.Lax),
  path       = Some(Path("/"))
)

val token = Cookie.Response(
  name       = "morbid-token",
  content    = "",
  maxAge     = Some(1.days),
  isHttpOnly = true,
  sameSite   = Some(SameSite.Lax),
  path       = Some(Path("/"))
)

extension (r: Response) {
  def loggedIn(tk: String): Response = r.addCookie(auth).addCookie(token.copy(content = tk))
  def logOff              : Response = r.addCookie(auth.copy(maxAge = Some(0.seconds))).addCookie(token.copy(maxAge = Some(0.seconds)))
}