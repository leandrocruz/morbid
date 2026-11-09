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
/** The admin always works on behalf of a specific `application` — the one picked
  * in the UI's app selector and forwarded via the `X-Admin-App` header. Every
  * manager call that targets a per-app morbid route takes `ApplicationCode` as a
  * given. Auth routes and app-crud routes are application-agnostic and don't. */
trait MorbidGateway {

  // auth (application-agnostic)
  def loginWithFirebase  (firebaseToken: String)                             : Task[(Token, String)]
  def loginProvider      (email: Email)                                      : Task[GetProviderResponse]
  def verify             (rawToken: RawToken)                                : Task[Token]
  def logoff             (rawToken: RawToken)                                : Task[Unit]

  // accounts (manager routes; require root account; scoped to the chosen app)
  def accounts           ()                           (using RawToken, ApplicationCode) : Task[Seq[RawAccount]]
  def allAccounts        ()                           (using RawToken)                  : Task[Seq[RawAccount]]
  def storeAccount       (req: StoreAccountRequest)   (using RawToken, ApplicationCode) : Task[RawAccount]
  def removeAccount      (account: AccountId)         (using RawToken, ApplicationCode) : Task[Boolean]

  // users
  def usersOfAccount     (account: AccountId)         (using RawToken, ApplicationCode) : Task[Seq[RawUserEntry]]
  def storeUserFor       (account: AccountId, req: StoreUserRequest)(using RawToken, ApplicationCode) : Task[RawUserEntry]
  def removeUserFrom     (account: AccountId, code: UserCode)(using RawToken, ApplicationCode) : Task[Boolean]
  def passwordChange     (req: ChangePasswordRequest) (using RawToken, ApplicationCode) : Task[Boolean]
  def passwordResetLink  (req: RequestPasswordRequestLink)(using RawToken, ApplicationCode) : Task[PasswordResetLink]
  def setPin             (req: SetUserPin)            (using RawToken, ApplicationCode) : Task[Boolean]

  // groups — scoped per-(account, app); the acc comes from the URL and the app is picked on the Groups page
  def groupsOfApp        (app: ApplicationCode, acc: AccountId)(using RawToken) : Task[Seq[RawGroup]]
  def usersInGroup       (app: ApplicationCode, acc: AccountId, grp: GroupCode)(using RawToken) : Task[Seq[RawUserEntry]]
  def storeGroup         (app: ApplicationCode, req: StoreGroupRequest)(using RawToken): Task[RawGroup]
  def removeGroup        (app: ApplicationCode, req: RemoveGroupRequest)(using RawToken): Task[Long]

  // applications (list/CRUD — application-agnostic)
  def applications       ()                                     (using RawToken) : Task[Seq[RawApplicationDetails]]
  def accountApps        (acc: AccountId)                        (using RawToken) : Task[Seq[RawApplicationDetails]]
  def linkAccountApp     (acc: AccountId, code: ApplicationCode) (using RawToken) : Task[Boolean]
  def unlinkAccountApp   (acc: AccountId, code: ApplicationCode) (using RawToken) : Task[Boolean]
  def createApplication  (req: CreateApplicationRequest)(using RawToken)     : Task[RawApplicationDetails]
  def updateApplication  (req: UpdateApplicationRequest)(using RawToken)     : Task[RawApplicationDetails]
  def removeApplication  (id: ApplicationId)          (using RawToken)       : Task[Long]

  // roles (app is explicit — the app whose roles we're looking at)
  def rolesOfApp         (app: ApplicationCode)       (using RawToken)       : Task[Seq[RawRole]]

  // tenants (routed under /app/:app/manager/tenants on morbid-server; app is from the header)
  def tenants            ()                                      (using RawToken) : Task[Seq[RawTenantDetails]]
  def storeTenant        (req: StoreTenantRequest)               (using RawToken) : Task[RawTenantDetails]
  def updateTenant       (id: TenantId, req: StoreTenantRequest) (using RawToken) : Task[RawTenantDetails]
  def removeTenant       (id: TenantId)                          (using RawToken) : Task[Long]

  // identity providers (per account; scoped to the chosen app)
  def providersOfAccount (account: AccountId)         (using RawToken, ApplicationCode) : Task[Seq[RawIdentityProvider]]
  def storeProvider      (account: AccountId, req: StoreIdentityProviderRequest)(using RawToken, ApplicationCode) : Task[RawIdentityProvider]
  def updateProvider     (account: AccountId, id: ProviderId, req: StoreIdentityProviderRequest)(using RawToken, ApplicationCode) : Task[RawIdentityProvider]
  def removeProvider     (account: AccountId, id: ProviderId)(using RawToken, ApplicationCode) : Task[Long]

  // api keys (service accounts per account; scoped to the chosen app)
  def listApiKeys        (account: AccountId)         (using RawToken, ApplicationCode) : Task[Seq[RawUserEntry]]
  def issueApiKey        (account: AccountId, req: CreateApiKeyRequest)(using RawToken, ApplicationCode) : Task[ApiKeyIssued]
  def removeApiKey       (account: AccountId, code: UserCode)(using RawToken, ApplicationCode) : Task[Boolean]
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

  override def accounts()(using token: RawToken, app: ApplicationCode): Task[Seq[RawAccount]] =
    client.managerGetAccounts(using token, app)

  override def allAccounts()(using token: RawToken): Task[Seq[RawAccount]] =
    get[Seq[RawAccount]](Some(token), systemManagerUrl("accounts/all"))

  override def storeAccount(req: StoreAccountRequest)(using token: RawToken, app: ApplicationCode): Task[RawAccount] =
    client.managerStoreAccount(req)(using token, app)

  override def removeAccount(account: AccountId)(using token: RawToken, app: ApplicationCode): Task[Boolean] =
    client.managerRemoveAccount(account)(using token, app)

  override def usersOfAccount(account: AccountId)(using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]] =
    client.managerGetUsers(account)(using token, app)

  override def storeUserFor(account: AccountId, req: StoreUserRequest)(using token: RawToken, app: ApplicationCode): Task[RawUserEntry] =
    client.managerStoreUser(req, account)(using token, app)

  override def removeUserFrom(account: AccountId, code: UserCode)(using token: RawToken, app: ApplicationCode): Task[Boolean] =
    client.managerRemoveUser(account, code)(using token, app)

  override def passwordChange(req: ChangePasswordRequest)(using token: RawToken, app: ApplicationCode): Task[Boolean] =
    client.passwordChange(req)(using token, app)

  override def passwordResetLink(req: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode): Task[PasswordResetLink] =
    client.passwordResetLink(req)(using token, app)

  override def setPin(req: SetUserPin)(using token: RawToken, app: ApplicationCode): Task[Boolean] =
    client.setPin(req)(using token, app)

  override def groupsOfApp(application: ApplicationCode, acc: AccountId)(using token: RawToken): Task[Seq[RawGroup]] =
    get[Seq[RawGroup]](Some(token), systemManagerUrl(s"account/${AccountId.value(acc)}/apps/${ApplicationCode.value(application)}/groups"))

  override def usersInGroup(application: ApplicationCode, acc: AccountId, grp: GroupCode)(using token: RawToken): Task[Seq[RawUserEntry]] =
    get[Seq[RawUserEntry]](Some(token), systemManagerUrl(s"account/${AccountId.value(acc)}/apps/${ApplicationCode.value(application)}/groups/${GroupCode.value(grp)}/users"))

  override def storeGroup(application: ApplicationCode, req: StoreGroupRequest)(using token: RawToken): Task[RawGroup] =
    client.storeGroup(req)(using token, application)

  override def removeGroup(application: ApplicationCode, req: RemoveGroupRequest)(using token: RawToken): Task[Long] =
    client.removeGroup(req)(using token, application)

  /** The morbid-server manager routes carry an `:app` path segment that the
    * system-wide (`manager/applications`, `manager/account/:acc/apps`) handlers
    * ignore. We pass [[cfg.morbid.application]] as a placeholder so the URL is
    * well-formed without forcing an `ApplicationCode` on callers that have no
    * natural one to provide (e.g. building the LoginResponse before the admin
    * has picked an app). */
  private def systemManagerUrl(suffix: String): String =
    s"/app/${cfg.application}/manager/$suffix"

  override def applications()(using token: RawToken): Task[Seq[RawApplicationDetails]] =
    get[Seq[RawApplicationDetails]](Some(token), systemManagerUrl("applications"))

  override def accountApps(acc: AccountId)(using token: RawToken): Task[Seq[RawApplicationDetails]] =
    get[Seq[RawApplicationDetails]](Some(token), systemManagerUrl(s"account/${AccountId.value(acc)}/apps"))

  override def linkAccountApp(acc: AccountId, code: ApplicationCode)(using token: RawToken): Task[Boolean] =
    post[String, Boolean](Some(token), systemManagerUrl(s"account/${AccountId.value(acc)}/apps/${ApplicationCode.value(code)}"), "")

  override def unlinkAccountApp(acc: AccountId, code: ApplicationCode)(using token: RawToken): Task[Boolean] =
    delete[Boolean](Some(token), systemManagerUrl(s"account/${AccountId.value(acc)}/apps/${ApplicationCode.value(code)}"))

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
    get[Seq[RawRole]](Some(token), systemManagerUrl(s"applications/${ApplicationCode.value(application)}/roles"))

  /* tenants / providers / api-keys / application-delete are not on MorbidClient yet,
     so we hit the server with raw HTTP under the chosen application
     path ("/app/:app/manager/..."). */

  private def managerUrl(path: String)(using app: ApplicationCode): String =
    s"/app/${ApplicationCode.value(app)}/manager/$path"

  private def managerAccountUrl(account: AccountId, path: String)(using app: ApplicationCode): String =
    s"/app/${ApplicationCode.value(app)}/manager/account/${AccountId.value(account)}/$path"

  private def put[R, T](token: Option[RawToken], url: String, req: R)(using JsonDecoder[T], JsonEncoder[R]): Task[T] = {
    for
      base <- ZIO.fromEither(URL.decode(url)).mapError(e => Exception(s"Bad URL: $e"))
      r     = Request(method = Method.PUT, url = base, headers = applicationJson ++ token.map(morbidToken).getOrElse(Headers.empty), body = Body.fromString(req.toJson), version = Version.Default, remoteAddress = None, remoteCertificate = None)
      res  <- perform(r)
      _    <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
      out  <- res.body.parse[T]().mapError(_ => ReturnResponseError(res))
    yield out
  }

  override def tenants()(using token: RawToken): Task[Seq[RawTenantDetails]] =
    get[Seq[RawTenantDetails]](Some(token), systemManagerUrl("tenants"))

  override def storeTenant(req: StoreTenantRequest)(using token: RawToken): Task[RawTenantDetails] =
    post[StoreTenantRequest, RawTenantDetails](Some(token), systemManagerUrl("tenants"), req)

  override def updateTenant(id: TenantId, req: StoreTenantRequest)(using token: RawToken): Task[RawTenantDetails] =
    put[StoreTenantRequest, RawTenantDetails](Some(token), systemManagerUrl(s"tenants/${TenantId.value(id)}"), req)

  override def removeTenant(id: TenantId)(using token: RawToken): Task[Long] =
    delete[Long](Some(token), systemManagerUrl(s"tenants/${TenantId.value(id)}"))

  override def providersOfAccount(account: AccountId)(using token: RawToken, app: ApplicationCode): Task[Seq[RawIdentityProvider]] =
    get[Seq[RawIdentityProvider]](Some(token), managerAccountUrl(account, "providers"))

  override def storeProvider(account: AccountId, req: StoreIdentityProviderRequest)(using token: RawToken, app: ApplicationCode): Task[RawIdentityProvider] =
    post[StoreIdentityProviderRequest, RawIdentityProvider](Some(token), managerAccountUrl(account, "providers"), req)

  override def updateProvider(account: AccountId, id: ProviderId, req: StoreIdentityProviderRequest)(using token: RawToken, app: ApplicationCode): Task[RawIdentityProvider] =
    put[StoreIdentityProviderRequest, RawIdentityProvider](Some(token), managerAccountUrl(account, s"providers/${ProviderId.value(id)}"), req)

  override def removeProvider(account: AccountId, id: ProviderId)(using token: RawToken, app: ApplicationCode): Task[Long] =
    delete[Long](Some(token), managerAccountUrl(account, s"providers/${ProviderId.value(id)}"))

  override def listApiKeys(account: AccountId)(using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]] =
    get[Seq[RawUserEntry]](Some(token), managerAccountUrl(account, "api-keys"))

  override def issueApiKey(account: AccountId, req: CreateApiKeyRequest)(using token: RawToken, app: ApplicationCode): Task[ApiKeyIssued] =
    post[CreateApiKeyRequest, ApiKeyIssued](Some(token), managerAccountUrl(account, "api-keys"), req)

  override def removeApiKey(account: AccountId, code: UserCode)(using token: RawToken, app: ApplicationCode): Task[Boolean] =
    delete[Boolean](Some(token), managerAccountUrl(account, s"api-keys/${UserCode.value(code)}"))

  override def removeApplication(id: ApplicationId)(using token: RawToken): Task[Long] =
    delete[Long](Some(token), s"/application/${ApplicationId.value(id)}")
}

object MorbidGateway {
  val layer: ZLayer[AppConfig & MorbidClient, Nothing, MorbidGateway] =
    ZLayer.fromFunction { (cfg: AppConfig, client: MorbidClient) =>
      HttpMorbidGateway(cfg.morbid, client): MorbidGateway
    }
}
