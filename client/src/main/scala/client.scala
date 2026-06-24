package morbid

import zio.*

object client {

  import guara.errors.{ReturnResponseError, ReturnUnifiedError}
  import guara.uef
  import guara.utils.queryParams
  import io.jsonwebtoken.{Jws, Jwts}
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.domain.requests.{*, given}
  import morbid.domain.token.*
  import morbid.types.*
  import zio.http.*
  import zio.json.*

  import java.nio.file.{Files, Paths}
  import java.time.{LocalDateTime, ZoneId, ZonedDateTime}
  import java.util.Base64
  import javax.crypto.spec.SecretKeySpec

  trait MorbidClient {
    def proxy             (request: Request)                                                                            : Task[Response]
    def provision         (request: ProvisionRequest)                                                                   : Task[Token]
    def provisionRaw      (request: ProvisionRequest)                                                                   : Task[Response]
    def accountByIdentifier(request: FindAccountByIdentifierRequest)                                                    : Task[Option[RawAccount]]
    def tokenFrom         (token: RawToken)                                                                             : Task[Token]
    def groups                                                             (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupsByCode      (groups: Seq[GroupCode])                         (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupByCode       (group: GroupCode)                               (using token: RawToken, app: ApplicationCode): Task[Option[RawGroup]]
    def usersByGroupByCode(group: GroupCode)                               (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def groupsByUser      (request: GetUserGroupsRequest)                  (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def setUserGroups     (request: SetUserGroupsRequest)                  (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def users                                                              (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def roles                                                              (using token: RawToken, app: ApplicationCode): Task[Seq[RawRole]]
    def storeGroup        (request: StoreGroupRequest)                     (using token: RawToken, app: ApplicationCode): Task[RawGroup]
    def removeGroup       (request: RemoveGroupRequest)                    (using token: RawToken, app: ApplicationCode): Task[Long]
    def storeUser         (request: StoreUserRequest)                      (using token: RawToken, app: ApplicationCode): Task[RawUserEntry]
    def removeUser        (request: RemoveUserRequest)                     (using token: RawToken, app: ApplicationCode): Task[Long]
    def passwordResetLink (request: RequestPasswordRequestLink)            (using token: RawToken, app: ApplicationCode): Task[PasswordResetLink]
    def passwordChange    (request: ChangePasswordRequest)                 (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def setPin            (request: SetUserPin)                            (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def validatePin       (request: ValidateUserPin)                       (using token: RawToken                      ): Task[Boolean]
    def emailLoginLink    (request: LoginViaEmailLinkRequest)              (using                  app: ApplicationCode): Task[LoginViaEmailLinkResponse]
    def managerGetUsers     (account: AccountId)                           (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def managerStoreUser    (request: StoreUserRequest, account: AccountId)(using token: RawToken, app: ApplicationCode): Task[RawUserEntry]
    def managerRemoveUser   (account: AccountId, code: UserCode)           (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def managerGetAccounts                                                 (using token: RawToken, app: ApplicationCode): Task[Seq[RawAccount]]
    def managerStoreAccount (request: StoreAccountRequest)                 (using token: RawToken, app: ApplicationCode): Task[RawAccount]
    def managerRemoveAccount(account: AccountId)                           (using token: RawToken, app: ApplicationCode): Task[Boolean]
  }

  case class MorbidClientConfig(url: String, mode: String = "remote", key: Option[String] = None, timezone: Option[String] = None)

  object MorbidClient {

    val layer = ZLayer {
      for {
        config <- ZIO.service[MorbidClientConfig]
        scope  <- ZIO.service[Scope]
        client <- ZIO.service[Client]
        url    <- ZIO.fromEither(URL.decode(config.url))
        remote =  RemoteMorbidClient(url, client, scope)
        impl   <- config.mode match
          case "local" => LocalMorbidClient.make(config, remote)
          case _       => ZIO.succeed(remote)
      } yield impl
    }

    def fake(app: ApplicationCode) = ZLayer.succeed(FakeMorbidClient(app))
  }

  case class RemoteMorbidClient(base: URL, client: Client, scope: Scope) extends MorbidClient {

    case class SimpleToken(token: RawToken)

    given JsonEncoder[SimpleToken] = DeriveJsonEncoder.gen

    private val applicationJson = Headers(Chunk(Header.ContentType(MediaType("application", "json"))))
    private def morbidToken(token: RawToken) = Headers(Chunk(Header.Custom(morbid.MorbidHeaders.Token, token.string)))

    // ZClient.batched fully buffers the response body before returning. Using ZClient.request
    // here returns a streaming response whose body is bound to the request scope — by the time
    // callers (e.g. narrowResponse in presto-api) try to read the body, the underlying connection
    // has been released and body.asString hangs forever waiting for bytes that never arrive.
    private def perform(request: Request): Task[Response] =
      ZClient.batched(request).provide(ZLayer.succeed(client))

    override def proxy(request: Request): Task[Response] = {
      for {
        resp <- perform(request.copy(url = base ++ request.url))
      } yield resp
    }

    override def provisionRaw(request: ProvisionRequest): Task[Response] = perform(Request.post(base / "provision", Body.fromString(request.toJson)).copy(headers = applicationJson))
    override def provision(request: ProvisionRequest)   : Task[Token]    = post[ProvisionRequest, Token](None, base / "provision", request)
    override def tokenFrom(token: RawToken)             : Task[Token]    = post[SimpleToken     , Token](Some(token), base / "verify", SimpleToken(token))
    override def accountByIdentifier(request: FindAccountByIdentifierRequest): Task[Option[RawAccount]] = post[FindAccountByIdentifierRequest, Option[RawAccount]](None, base / "account" / "by-identifier", request)

    private def exec[T](token: Option[RawToken], req: Request)(using dec: JsonDecoder[T]): Task[T] = {

      def badGateway(cause: Throwable) = {
        ReturnUnifiedError(
          message = s"Error calling Morbid '${req.url.encode}'",
          cause   = Some(cause)
        )
      }

      def handleUEF(res: Response, body: String): Task[T] = {
        val headers = Headers(res.headers.filterNot(_.headerType == Header.ContentLength)) //FIXME: should we remove the ContentLength header?
        ZIO.fail {
          ReturnResponseError(
            res.copy(headers = headers, body = Body.fromString(body)) //ensures the MorbidClient caller can read the body
          )
        }
      }

      def handleParseError(res: Response, body: String)(error: String) = {
        ReturnUnifiedError(
          message = s"Error parsing morbid server response: '$error'",
          status  = res.status.code,
          cause   = Some(Exception(s"Morbid '${req.url.encode}' returned ${res.status.code}: $body"))
        )
      }

      for
        _      <- ZIO.logInfo(s"Calling '${req.url.encode}'")
        res    <- perform(req.copy(headers = req.headers ++ token.map(morbidToken).getOrElse(Headers.empty))).mapError(badGateway)
        isUEF  = res.headers.exists(uef.isUEFHeader)
        _      <- ZIO.logInfo(s"Result is ${res.status.code} (uef ? $isUEF)")
        str    <- res.body.asString
        _      <- ZIO.when(isUEF) { handleUEF(res, str) }
        result <- ZIO.fromEither(str.fromJson[T]).mapError(handleParseError(res, str))
      yield result
    }

    private def delete[T] (token: Option[RawToken], url: URL)           (using dec: JsonDecoder[T])                     : Task[T] = exec(token, Request.get(url))
    private def get [T]   (token: Option[RawToken], url: URL)           (using dec: JsonDecoder[T])                     : Task[T] = exec(token, Request.get(url))
    private def post[R, T](token: Option[RawToken], url: URL, req: R)   (using dec: JsonDecoder[T], enc: JsonEncoder[R]): Task[T] = exec(token, Request.post(url, Body.fromString(req.toJson)).copy(headers = applicationJson))

    override def groupByCode       (group: GroupCode)                   (using token: RawToken, app: ApplicationCode) = get [Option[RawGroup]]                                    (Some(token),  base / "app" / ApplicationCode.value(app) / "group")
    override def storeGroup        (request: StoreGroupRequest)         (using token: RawToken, app: ApplicationCode) = post[StoreGroupRequest, RawGroup]                         (Some(token),  base / "app" / ApplicationCode.value(app) / "group", request)
    override def removeGroup       (request: RemoveGroupRequest)        (using token: RawToken, app: ApplicationCode) = post[RemoveGroupRequest, Long]                            (Some(token),  base / "app" / ApplicationCode.value(app) / "group" / "delete", request)
    override def groups                                                 (using token: RawToken, app: ApplicationCode) = get [Seq[RawGroup]]                                       (Some(token),  base / "app" / ApplicationCode.value(app) / "groups")
    override def groupsByCode      (groups: Seq[GroupCode])             (using token: RawToken, app: ApplicationCode) = get [Seq[RawGroup]]                                       (Some(token), (base / "app" / ApplicationCode.value(app) / "groups").queryParams(QueryParams(Map("code" -> Chunk.fromIterator(groups.map(GroupCode.value).iterator)))))
    override def usersByGroupByCode(group: GroupCode)                   (using token: RawToken, app: ApplicationCode) = get [Seq[RawUserEntry]]                                   (Some(token),  base / "app" / ApplicationCode.value(app) / "group" / GroupCode.value(group) / "users")
    override def groupsByUser      (request: GetUserGroupsRequest)      (using token: RawToken, app: ApplicationCode) = post[GetUserGroupsRequest, Seq[RawGroup]]                 (Some(token),  base / "app" / ApplicationCode.value(app) / "user"  / "groups" / "find", request)
    override def setUserGroups     (request: SetUserGroupsRequest)      (using token: RawToken, app: ApplicationCode) = post[SetUserGroupsRequest, Boolean]                       (Some(token),  base / "app" / ApplicationCode.value(app) / "user"  / "groups", request)
    override def storeUser         (request: StoreUserRequest)          (using token: RawToken, app: ApplicationCode) = post[StoreUserRequest, RawUserEntry]                      (Some(token),  base / "app" / ApplicationCode.value(app) / "user", request)
    override def removeUser        (request: RemoveUserRequest)         (using token: RawToken, app: ApplicationCode) = post[RemoveUserRequest, Long]                             (Some(token),  base / "app" / ApplicationCode.value(app) / "user" / "delete", request)
    override def users                                                  (using token: RawToken, app: ApplicationCode) = get [Seq[RawUserEntry]]                                   (Some(token),  base / "app" / ApplicationCode.value(app) / "users")
    override def roles                                                  (using token: RawToken, app: ApplicationCode) = get [Seq[RawRole]]                                        (Some(token),  base / "app" / ApplicationCode.value(app) / "roles")
    override def passwordResetLink (request: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode) = post[RequestPasswordRequestLink, PasswordResetLink]       (Some(token),  base / "app" / ApplicationCode.value(app) / "password" / "reset", request)
    override def passwordChange    (request: ChangePasswordRequest)     (using token: RawToken, app: ApplicationCode) = post[ChangePasswordRequest, Boolean]                      (Some(token),  base / "app" / ApplicationCode.value(app) / "password" / "change", request)
    override def setPin            (request: SetUserPin)                (using token: RawToken, app: ApplicationCode) = post[SetUserPin, Boolean]                                 (Some(token),  base / "app" / ApplicationCode.value(app) / "user" / "pin", request)
    override def validatePin       (request: ValidateUserPin)           (using token: RawToken                      ) = post[ValidateUserPin, Boolean]                            (Some(token),  base                                      / "user" / "pin" / "validate", request)
    override def emailLoginLink    (request: LoginViaEmailLinkRequest)  (using                  app: ApplicationCode) = post[LoginViaEmailLinkRequest, LoginViaEmailLinkResponse] (None       ,  base / "app" / ApplicationCode.value(app) / "login" / "email", request)

    override def managerGetUsers     (account: AccountId)                           (using token: RawToken, app: ApplicationCode) = get[Seq[RawUserEntry]]               (Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "account" / AccountId.value(account).toString / "users")
    override def managerStoreUser    (request: StoreUserRequest, account: AccountId)(using token: RawToken, app: ApplicationCode) = post[StoreUserRequest, RawUserEntry] (Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "account" / AccountId.value(account).toString / "user", request)
    override def managerRemoveUser   (account: AccountId, code: UserCode)           (using token: RawToken, app: ApplicationCode) = delete[Boolean]                      (Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "account" / AccountId.value(account).toString / "user" / UserCode.value(code))
    override def managerGetAccounts                                                 (using token: RawToken, app: ApplicationCode) = get[Seq[RawAccount]]                 (Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "accounts")
    override def managerStoreAccount (request: StoreAccountRequest)                 (using token: RawToken, app: ApplicationCode) = post[StoreAccountRequest, RawAccount](Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "account", request)
    override def managerRemoveAccount(account: AccountId)                           (using token: RawToken, app: ApplicationCode) = delete[Boolean]                      (Some(token),  base / "app" / ApplicationCode.value(app) / "manager" / "account" / AccountId.value(account).toString)
  }

  case class LocalMorbidClient(parser: io.jsonwebtoken.JwtParser, zone: ZoneId, remote: RemoteMorbidClient) extends MorbidClient {

    override def tokenFrom(token: RawToken): Task[Token] = {

      def asToken(str: String): Task[Token] =
        ZIO.fromEither(str.fromJson[Token]).mapError(new Exception(_))

      def isExpired(token: Token, now: ZonedDateTime): Boolean =
        token.expires.exists(now.isAfter)

      for
        _       <- ZIO.logDebug("Verifying token locally")
        generic <- ZIO.attempt(parser.parse(token.string))
        str     <- ZIO.attempt(generic.accept(Jws.CONTENT).getPayload)
        token   <- asToken(new String(str))
        now     <- Clock.localDateTime
        expired =  isExpired(token, now.atZone(zone))
        _       <- ZIO.when(expired) { ZIO.fail(Exception(s"Token is expired since '${token.expires.getOrElse("???")}'")) }
      yield token
    }

    override def proxy             (request: Request)                                                                 = remote.proxy(request)
    override def provision         (request: ProvisionRequest)                                                        = remote.provision(request)
    override def provisionRaw      (request: ProvisionRequest)                                                        = remote.provisionRaw(request)
    override def accountByIdentifier(request: FindAccountByIdentifierRequest)                                         = remote.accountByIdentifier(request)
    override def groups                                                 (using token: RawToken, app: ApplicationCode) = remote.groups
    override def groupsByCode      (groups: Seq[GroupCode])             (using token: RawToken, app: ApplicationCode) = remote.groupsByCode(groups)
    override def groupByCode       (group: GroupCode)                   (using token: RawToken, app: ApplicationCode) = remote.groupByCode(group)
    override def usersByGroupByCode(group: GroupCode)                   (using token: RawToken, app: ApplicationCode) = remote.usersByGroupByCode(group)
    override def groupsByUser      (request: GetUserGroupsRequest)      (using token: RawToken, app: ApplicationCode) = remote.groupsByUser(request)
    override def setUserGroups     (request: SetUserGroupsRequest)      (using token: RawToken, app: ApplicationCode) = remote.setUserGroups(request)
    override def users                                                  (using token: RawToken, app: ApplicationCode) = remote.users
    override def roles                                                  (using token: RawToken, app: ApplicationCode) = remote.roles
    override def storeGroup        (request: StoreGroupRequest)         (using token: RawToken, app: ApplicationCode) = remote.storeGroup(request)
    override def removeGroup       (request: RemoveGroupRequest)        (using token: RawToken, app: ApplicationCode) = remote.removeGroup(request)
    override def storeUser         (request: StoreUserRequest)          (using token: RawToken, app: ApplicationCode) = remote.storeUser(request)
    override def removeUser        (request: RemoveUserRequest)         (using token: RawToken, app: ApplicationCode) = remote.removeUser(request)
    override def passwordResetLink (request: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode) = remote.passwordResetLink(request)
    override def passwordChange    (request: ChangePasswordRequest)     (using token: RawToken, app: ApplicationCode) = remote.passwordChange(request)
    override def setPin            (request: SetUserPin)                (using token: RawToken, app: ApplicationCode) = remote.setPin(request)
    override def validatePin       (request: ValidateUserPin)           (using token: RawToken                      ) = remote.validatePin(request)
    override def emailLoginLink    (request: LoginViaEmailLinkRequest)  (using                  app: ApplicationCode) = remote.emailLoginLink(request)
    override def managerGetUsers     (account: AccountId)                           (using token: RawToken, app: ApplicationCode) = remote.managerGetUsers(account)
    override def managerStoreUser    (request: StoreUserRequest, account: AccountId)(using token: RawToken, app: ApplicationCode) = remote.managerStoreUser(request, account)
    override def managerRemoveUser   (account: AccountId, code: UserCode)           (using token: RawToken, app: ApplicationCode) = remote.managerRemoveUser(account, code)
    override def managerGetAccounts                                                 (using token: RawToken, app: ApplicationCode) = remote.managerGetAccounts
    override def managerStoreAccount (request: StoreAccountRequest)                 (using token: RawToken, app: ApplicationCode) = remote.managerStoreAccount(request)
    override def managerRemoveAccount(account: AccountId)                           (using token: RawToken, app: ApplicationCode) = remote.managerRemoveAccount(account)
  }

  object LocalMorbidClient {
    def make(config: MorbidClientConfig, remote: RemoteMorbidClient): Task[LocalMorbidClient] = {
      for
        path    <- ZIO.fromOption(config.key).orElseFail(Exception("MorbidClientConfig.key is required for local mode"))
        zone    =  ZoneId.of(config.timezone.getOrElse("America/Sao_Paulo"))
        _       <- ZIO.logInfo(s"Loading JWT key from '$path' for local token verification")
        bytes   <- ZIO.attempt(Files.readAllBytes(Paths.get(path)))
        decoded <- ZIO.attempt(Base64.getDecoder.decode(bytes))
        key     =  new SecretKeySpec(decoded, 0, decoded.length, "HmacSHA512")
        parser  =  Jwts.parser().verifyWith(key).build()
      yield LocalMorbidClient(parser, zone, remote)
    }
  }

  case class FakeMorbidClient(appcode: ApplicationCode) extends MorbidClient {

    private val _adm = RawRole(
      id          = RoleId.of(1),
      created     = LocalDateTime.now(),
      deleted     = None,
      code        = RoleCode.of("adm"),
      name        = RoleName.of("Admin"),
      permissions = Seq.empty
    )

    private val _groups = Seq(
      RawGroup(GroupId.of(1), LocalDateTime.now(), None, GroupCode.of("admin"), GroupName.of("Admin"), roles = Seq(_adm)),
      RawGroup(GroupId.of(2), LocalDateTime.now(), None, GroupCode.of("all"), GroupName.of("All")),
      RawGroup(GroupId.of(3), LocalDateTime.now(), None, GroupCode.of("g0"), GroupName.of("Group 0")),
    )

    private val _users = Seq(
      RawUserEntry(UserId.of(1), LocalDateTime.now(), None, AccountId.of(1), None, code = UserCode.of("usr1"), active = true, Email.of("usr1@email.com")),
      RawUserEntry(UserId.of(2), LocalDateTime.now(), None, AccountId.of(1), None, code = UserCode.of("usr2"), active = true, Email.of("usr2@email.com")),
      RawUserEntry(UserId.of(3), LocalDateTime.now(), None, AccountId.of(1), None, code = UserCode.of("usr3"), active = true, Email.of("usr3@email.com"))
    )

    override def validatePin       (request: ValidateUserPin)            (using token: RawToken)                        = ZIO.succeed(true)
    override def groups                                                  (using token: RawToken, app: ApplicationCode) = ZIO.succeed(_groups)
    override def users                                                   (using token: RawToken, app: ApplicationCode) = ZIO.succeed(_users)
    override def groupByCode       (group: GroupCode)                    (using token: RawToken, app: ApplicationCode) = ZIO.succeed(_groups.find(_.code == group))
    override def groupsByCode      (groups: Seq[GroupCode])              (using token: RawToken, app: ApplicationCode) = ZIO.succeed { _groups.filter(g => groups.contains(g.code)) }
    override def proxy             (request: Request)                                                                  = ZIO.fail(Exception("TODO"))
    override def provision         (request: ProvisionRequest)                                                         = ZIO.fail(Exception("TODO"))
    override def provisionRaw      (request: ProvisionRequest)                                                         = ZIO.fail(Exception("TODO"))
    override def accountByIdentifier(request: FindAccountByIdentifierRequest)                                          = ZIO.fail(Exception("TODO"))
    override def usersByGroupByCode(group: GroupCode)                    (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def groupsByUser      (request: GetUserGroupsRequest)       (using token: RawToken, app: ApplicationCode) = ZIO.succeed(_groups)
    override def setUserGroups     (request: SetUserGroupsRequest)       (using token: RawToken, app: ApplicationCode) = ZIO.succeed(true)
    override def roles                                                   (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def storeGroup        (request: StoreGroupRequest)          (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def storeUser         (request: StoreUserRequest)           (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def setPin            (request: SetUserPin)                 (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def passwordResetLink (request: RequestPasswordRequestLink) (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def removeGroup       (request: RemoveGroupRequest)         (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def removeUser        (request: RemoveUserRequest)          (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def emailLoginLink    (request: LoginViaEmailLinkRequest)   (using app: ApplicationCode)                  = ZIO.fail(Exception("TODO"))
    override def passwordChange    (request: ChangePasswordRequest)      (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))

    override def tokenFrom(token: RawToken): Task[Token] = ZIO.attempt {

      val app = CompactApplication(
        id      = ApplicationId.of(1),
        code    = appcode,
        groups  = _groups.map(CompactGroup.of)
      )

      Token(
        created = ZonedDateTime.now(),
        expires = None,
        user    = CompactUser(
          applications = Seq(app),
          details = RawUserDetails(
            tenant      = TenantId.of(1),
            tenantCode  = TenantCode.of("T1"),
            account     = AccountId.of(1),
            accountCode = AccountCode.of("acc1"),
            id          = UserId.of(1),
            code        = UserCode.of("usr1"),
            created     = LocalDateTime.now(),
            deleted     = None,
            kind        = None,
            active      = true,
            email       = Email.of("usr1@email.com")
          ),
        )
      )
    }
    
    override def managerGetUsers     (account: AccountId)                           (using token: RawToken, app: ApplicationCode) = ???
    override def managerStoreUser    (request: StoreUserRequest, account: AccountId)(using token: RawToken, app: ApplicationCode) = ???
    override def managerRemoveUser   (account: AccountId, code: UserCode)           (using token: RawToken, app: ApplicationCode) = ???
    override def managerGetAccounts                                                 (using token: RawToken, app: ApplicationCode) = ???
    override def managerStoreAccount (request: StoreAccountRequest)                 (using token: RawToken, app: ApplicationCode) = ???
    override def managerRemoveAccount(account: AccountId)                           (using token: RawToken, app: ApplicationCode) = ???
  }
}