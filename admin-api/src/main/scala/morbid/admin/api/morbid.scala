package morbid.admin.api

import guara.errors.{ReturnResponseError, ReturnResponseWithExceptionError}
import guara.utils.parse
import morbid.client.MorbidClient
import morbid.domain.raw.*
import morbid.domain.requests.*
import morbid.domain.token.{RawToken, Token, *}
import morbid.admin.api.codecs.given
import morbid.protocol.{given, *}
import morbid.types.*
import zio.*
import zio.http.*
import zio.json.*

/** Thin wrapper around MorbidClient + raw HTTP calls that aren't exposed by the client.
  * The admin-api acts on behalf of the authenticated admin user: every call forwards the
  * user's Morbid token (X-MorbidToken) so Morbid applies its own authorization rules.
  */
trait MorbidGateway {

  // auth
  def loginWithFirebase  (firebaseToken: String)                             : Task[(Token, String)]
  def loginProvider      (email: Email)                                      : Task[GetProviderResponse]
  def verify             (rawToken: RawToken)                                : Task[Token]
  def logoff             (rawToken: RawToken)                                : Task[Unit]

  // accounts (manager routes; require root account)
  def accounts           ()                           (using RawToken)       : Task[Seq[RawAccount]]
  def storeAccount       (req: StoreAccountRequest)   (using RawToken)       : Task[RawAccount]
  def removeAccount      (account: AccountId)         (using RawToken)       : Task[Boolean]

  // users
  def usersOfAccount     (account: AccountId)         (using RawToken)       : Task[Seq[RawUserEntry]]
  def storeUserFor       (account: AccountId, req: StoreUserRequest)(using RawToken): Task[RawUserEntry]
  def removeUserFrom     (account: AccountId, code: UserCode)(using RawToken): Task[Boolean]
  def passwordChange     (req: ChangePasswordRequest) (using RawToken)       : Task[Boolean]
  def passwordResetLink  (req: RequestPasswordRequestLink)(using RawToken)   : Task[PasswordResetLink]
  def setPin             (req: SetUserPin)            (using RawToken)       : Task[Boolean]

  // groups
  def groupsOfApp        (app: ApplicationCode)       (using RawToken)       : Task[Seq[RawGroup]]
  def storeGroup         (app: ApplicationCode, req: StoreGroupRequest)(using RawToken): Task[RawGroup]
  def removeGroup        (app: ApplicationCode, req: RemoveGroupRequest)(using RawToken): Task[Long]

  // applications
  def applications       ()                           (using RawToken)       : Task[Seq[RawApplicationDetails]]
  def createApplication  (req: CreateApplicationRequest)(using RawToken)     : Task[RawApplicationDetails]
  def updateApplication  (req: UpdateApplicationRequest)(using RawToken)     : Task[RawApplicationDetails]

  // roles
  def rolesOfApp         (app: ApplicationCode)       (using RawToken)       : Task[Seq[RawRole]]
}

case class VerifyGoogleTokenRequest(token: String)
object VerifyGoogleTokenRequest {
  given JsonCodec[VerifyGoogleTokenRequest] = DeriveJsonCodec.gen
}

/** Mirrors morbid's `GetLoginMode` request body (see server/shared.scala). */
case class GetLoginModeRequest(email: Email, tenant: Option[TenantCode] = None)
object GetLoginModeRequest {
  given JsonCodec[GetLoginModeRequest] = DeriveJsonCodec.gen
}

case class HttpMorbidGateway(cfg: MorbidCfg, client: MorbidClient) extends MorbidGateway {

  private val applicationJson           = Headers(Chunk(Header.ContentType(MediaType("application", "json"))))
  private def morbidToken(token: RawToken) = Headers(Chunk(Header.Custom("X-MorbidToken", token.string)))

  private def app: ApplicationCode = ApplicationCode.of(cfg.application)

  private def perform(request: Request): Task[Response] = client.proxy(request)

  private def exec[T](token: Option[RawToken], req: Request)(using dec: JsonDecoder[T]): Task[T] =
    for
      _      <- ZIO.log(s"Calling Morbid '${req.url.encode}'")
      res    <- perform(req.copy(headers = req.headers ++ token.map(morbidToken).getOrElse(Headers.empty)))
      _      <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
      result <- res.body.parse[T]().mapError(_ => ReturnResponseError(res))
    yield result

  private def get [T]   (token: Option[RawToken], url: String)        (using JsonDecoder[T])              : Task[T] = exec(token, Request.get(URL.decode(url).toOption.get))
  private def delete[T] (token: Option[RawToken], url: String)        (using JsonDecoder[T])              : Task[T] = exec(token, Request.delete(URL.decode(url).toOption.get))
  private def post[R, T](token: Option[RawToken], url: String, req: R)(using JsonDecoder[T], JsonEncoder[R]): Task[T] =
    exec(token, Request.post(URL.decode(url).toOption.get, Body.fromString(req.toJson)).copy(headers = applicationJson))

  private def postRaw(token: Option[RawToken], url: String, body: String): Task[Response] =
    val base = URL.decode(url).toOption.get
    val req  = Request.post(base, Body.fromString(body)).copy(headers = applicationJson)
    perform(req.copy(headers = req.headers ++ token.map(morbidToken).getOrElse(Headers.empty)))

  override def loginWithFirebase(firebaseToken: String): Task[(Token, String)] = {
    val body = VerifyGoogleTokenRequest(firebaseToken).toJson
    for
      res   <- postRaw(None, "/login", body)
      _     <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
      raw   <- res.body.asString
      token <- ZIO.fromEither(raw.fromJson[Token]).mapError(e => Exception(s"Error parsing login response: $e"))
      morbidCookie <- ZIO.fromOption(extractMorbidToken(res))
                        .orElseFail(Exception(s"Morbid /login did not return a morbid-token cookie. Headers: ${res.headers.toList.map(h => s"${h.headerName}=${h.renderedValue}").mkString("; ")}"))
    yield (token, morbidCookie)
  }

  /** Iterates every `Set-Cookie` response header and pulls out the `morbid-token=VALUE` pair.
    * zio-http's client returns these as untyped headers, so the typed `Header.SetCookie` extractor
    * does not match — we parse by header name + first `name=value` segment instead, which also
    * avoids the comma-in-`Expires` pitfall. */
  private def extractMorbidToken(res: Response): Option[String] = {
    val setCookieHeaders: List[String] = res.headers.toList.collect {
      case h if h.headerName.equalsIgnoreCase("set-cookie") => h.renderedValue
    }
    setCookieHeaders.iterator.flatMap { raw =>
      val firstPair = raw.takeWhile(_ != ';').trim
      val idx       = firstPair.indexOf('=')
      if idx > 0 then
        val name  = firstPair.substring(0, idx)
        val value = firstPair.substring(idx + 1)
        if name == "morbid-token" && value.nonEmpty then Some(value) else None
      else None
    }.nextOption()
  }

  override def loginProvider(email: Email): Task[GetProviderResponse] = {
    val body = GetLoginModeRequest(email).toJson
    for
      res <- postRaw(None, "/login/provider", body)
      _   <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
      raw <- res.body.asString
      out <- ZIO.fromEither(raw.fromJson[GetProviderResponse])
               .mapError(e => Exception(s"Error parsing /login/provider response: $e"))
    yield out
  }

  override def verify(rawToken: RawToken): Task[Token] = client.tokenFrom(rawToken)

  override def logoff(rawToken: RawToken): Task[Unit] =
    for
      res <- postRaw(Some(rawToken), "/logoff", "")
      _   <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
    yield ()

  override def accounts()(using token: RawToken): Task[Seq[RawAccount]] =
    client.managerGetAccounts(using token, app)

  override def storeAccount(req: StoreAccountRequest)(using token: RawToken): Task[RawAccount] =
    client.managerStoreAccount(req)(using token, app)

  override def removeAccount(account: AccountId)(using token: RawToken): Task[Boolean] =
    client.managerRemoveAccount(account)(using token, app)

  override def usersOfAccount(account: AccountId)(using token: RawToken): Task[Seq[RawUserEntry]] =
    client.managerGetUsers(account)(using token, app)

  override def storeUserFor(account: AccountId, req: StoreUserRequest)(using token: RawToken): Task[RawUserEntry] =
    client.managerStoreUser(req, account)(using token, app)

  override def removeUserFrom(account: AccountId, code: UserCode)(using token: RawToken): Task[Boolean] =
    client.managerRemoveUser(account, code)(using token, app)

  override def passwordChange(req: ChangePasswordRequest)(using token: RawToken): Task[Boolean] =
    client.passwordChange(req)(using token, app)

  override def passwordResetLink(req: RequestPasswordRequestLink)(using token: RawToken): Task[PasswordResetLink] =
    client.passwordResetLink(req)(using token, app)

  override def setPin(req: SetUserPin)(using token: RawToken): Task[Boolean] =
    client.setPin(req)(using token, app)

  override def groupsOfApp(application: ApplicationCode)(using token: RawToken): Task[Seq[RawGroup]] =
    client.groups(using token, application)

  override def storeGroup(application: ApplicationCode, req: StoreGroupRequest)(using token: RawToken): Task[RawGroup] =
    client.storeGroup(req)(using token, application)

  override def removeGroup(application: ApplicationCode, req: RemoveGroupRequest)(using token: RawToken): Task[Long] =
    client.removeGroup(req)(using token, application)

  override def applications()(using token: RawToken): Task[Seq[RawApplicationDetails]] =
    get[Seq[RawApplicationDetails]](Some(token), s"/applications")

  override def createApplication(req: CreateApplicationRequest)(using token: RawToken): Task[RawApplicationDetails] =
    post[CreateApplicationRequest, RawApplicationDetails](Some(token), "/application", req)

  override def updateApplication(req: UpdateApplicationRequest)(using token: RawToken): Task[RawApplicationDetails] =
    for
      base <- ZIO.fromEither(URL.decode("/application")).mapError(e => Exception(s"Bad URL: $e"))
      body  = req.toJson
      r     = Request(method = Method.PUT, url = base, headers = applicationJson ++ morbidToken(token), body = Body.fromString(body), version = Version.Default, remoteAddress = None, remoteCertificate = None)
      res  <- perform(r)
      _    <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
      out  <- res.body.parse[RawApplicationDetails]().mapError(_ => ReturnResponseError(res))
    yield out

  override def rolesOfApp(application: ApplicationCode)(using token: RawToken): Task[Seq[RawRole]] =
    client.roles(using token, application)
}

object MorbidGateway {
  val layer: ZLayer[AppConfig & MorbidClient, Nothing, MorbidGateway] =
    ZLayer.fromFunction { (cfg: AppConfig, client: MorbidClient) =>
      HttpMorbidGateway(cfg.morbid, client): MorbidGateway
    }
}
