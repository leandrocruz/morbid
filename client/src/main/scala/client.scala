package morbid

import zio.*

object client {

  import guara.errors.{ReturnResponseError, ReturnResponseWithExceptionError}
  import guara.utils.{parse, queryParams}
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.domain.requests.{*, given}
  import morbid.domain.token.*
  import morbid.types.*
  import zio.http.*
  import zio.json.*

  import java.time.{LocalDateTime, ZonedDateTime}

  trait MorbidClient {
    def proxy             (request: Request)                                                                : Task[Response]
    def tokenFrom         (token: RawToken)                                                                 : Task[Token]
    def groups                                                 (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupsByCode      (groups: Seq[GroupCode])             (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupByCode       (group: GroupCode)                   (using token: RawToken, app: ApplicationCode): Task[Option[RawGroup]]
    def usersByGroupByCode(group: GroupCode)                   (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def usersGroups                                            (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserGroup]]
    def users                                                  (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def roles                                                  (using token: RawToken, app: ApplicationCode): Task[Seq[RawRole]]
    def storeGroup        (request: StoreGroupRequest)         (using token: RawToken, app: ApplicationCode): Task[RawGroup]
    def removeGroup       (request: RemoveGroupRequest)        (using token: RawToken, app: ApplicationCode): Task[Long]
    def storeUser         (request: StoreUserRequest)          (using token: RawToken, app: ApplicationCode): Task[RawUserEntry]
    def removeUser        (request: RemoveUserRequest)         (using token: RawToken, app: ApplicationCode): Task[Long]
    def passwordResetLink (request: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode): Task[PasswordResetLink]
    def passwordChange    (request: ChangePasswordRequest)     (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def setPin            (request: SetUserPin)                (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def validatePin       (request: ValidateUserPin)           (using token: RawToken                      ): Task[Boolean]
    def emailLoginLink    (request: LoginViaEmailLinkRequest)  (using                  app: ApplicationCode): Task[LoginViaEmailLinkResponse]
    
    def managerGetUsers     (account: AccountId)                           (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def managerStoreUser    (request: StoreUserRequest, account: AccountId)(using token: RawToken, app: ApplicationCode): Task[RawUserEntry]
    def managerRemoveUser   (account: AccountId, code: UserCode)           (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def managerGetAccounts                                                 (using token: RawToken, app: ApplicationCode): Task[Seq[RawAccount]]
    def managerStoreAccount (request: StoreAccountRequest)                 (using token: RawToken, app: ApplicationCode): Task[RawAccount]
    def managerRemoveAccount(account: AccountId)                           (using token: RawToken, app: ApplicationCode): Task[Boolean]
  }

  case class MorbidClientConfig(url: String)

  object MorbidClient {

    val layer = ZLayer {
      for {
        config <- ZIO.service[MorbidClientConfig]
        scope  <- ZIO.service[Scope]
        client <- ZIO.service[Client]
        url    <- ZIO.fromEither(URL.decode(config.url))
      } yield RemoteMorbidClient(url, client, scope)
    }

    def fake(app: ApplicationCode) = ZLayer.succeed(FakeMorbidClient(app))
  }

  case class RemoteMorbidClient(base: URL, client: Client, scope: Scope) extends MorbidClient {

    case class SimpleToken(token: RawToken)

    given JsonEncoder[SimpleToken] = DeriveJsonEncoder.gen

    private val applicationJson = Headers(Chunk(Header.ContentType(MediaType("application", "json"))))
    private def morbidToken(token: RawToken) = Headers(Chunk(Header.Custom("X-MorbidToken", token.string)))

    private def perform(request: Request): Task[Response] = for {
      response <- ZClient.request(request).provideSome(ZLayer.succeed(scope), ZLayer.succeed(client))
    } yield response

    override def proxy(request: Request): Task[Response] = {
      for {
        resp <- perform(request.copy(url = base ++ request.url))
      } yield resp
    }

    override def tokenFrom(token: RawToken): Task[Token] = post[SimpleToken, Token](Some(token), base / "verify", SimpleToken(token))

    private def exec[T](token: Option[RawToken], req: Request)(using dec: JsonDecoder[T]): Task[T] = {

      def badGateway(message: String, cause: Option[Throwable] = None) = {
        val resp = Response.error(Status.BadGateway, message)
        cause match
          case Some(error) => ReturnResponseWithExceptionError(error, resp)
          case None        => ReturnResponseError(resp)
      }

      def warnings(response: Response) = response.headers.get("warning")

      for {
        _      <- ZIO.log(s"Calling '${req.url.encode}'")
        res    <- perform(req.copy(headers = req.headers ++ token.map(morbidToken).getOrElse(Headers.empty))).mapError(e => badGateway(s"Error calling Morbid '${req.url.encode}': ${e.getMessage}"))
        _      <- ZIO.when(res.status.code != 200) { ZIO.fail(ReturnResponseError(res)) }
        result <- res.body.parse[T]().mapError(_ => ReturnResponseError(res))
      } yield result
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
    override def usersGroups                                            (using token: RawToken, app: ApplicationCode) = get [Seq[RawUserGroup]]                                   (Some(token),  base / "app" / ApplicationCode.value(app) / "users" / "groups")
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
    override def usersByGroupByCode(group: GroupCode)                    (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
    override def usersGroups                                             (using token: RawToken, app: ApplicationCode) = ZIO.fail(Exception("TODO"))
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