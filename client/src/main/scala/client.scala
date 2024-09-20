package morbid

import zio.*

object client {

  import morbid.types.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.domain.token.{Token, RawToken}
  import morbid.domain.token.given
  import morbid.domain.requests.*
  import morbid.domain.requests.given
  import guara.utils.{parse, queryParams}
  import guara.errors.{ReturnResponseWithExceptionError, ReturnResponseError}
  import zio.http.*
  import zio.json.*

  trait MorbidClient {
    def proxy(request: Request): Task[Response]
    def tokenFrom(token: RawToken): Task[Token]
    def groups                                                 (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupsByCode      (groups: Seq[GroupCode])             (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupByCode       (group: GroupCode)                   (using token: RawToken, app: ApplicationCode): Task[Option[RawGroup]]
    def usersByGroupByCode(group: GroupCode)                   (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def users                                                  (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def roles                                                  (using token: RawToken, app: ApplicationCode): Task[Seq[RawRole]]
    def storeGroup        (request: StoreGroupRequest)         (using token: RawToken, app: ApplicationCode): Task[RawGroup]
    def removeGroup       (request: RemoveGroupRequest)        (using token: RawToken, app: ApplicationCode): Task[Long]
    def storeUser         (request: StoreUserRequest)          (using token: RawToken, app: ApplicationCode): Task[RawUserEntry]
    def removeUser        (request: RemoveUserRequest)         (using token: RawToken, app: ApplicationCode): Task[Long]
    def passwordResetLink (request: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode): Task[PasswordResetLink]
    def setPin            (request: SetUserPin)                (using token: RawToken, app: ApplicationCode): Task[Boolean]
    def validatePin       (request: ValidateUserPin)           (using token: RawToken                      ): Task[Boolean]
    def emailLoginLink    (request: LoginViaEmailLinkRequest)  (using                  app: ApplicationCode): Task[LoginViaEmailLinkResponse]
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
        result <- res.body.parse[T].mapError(_ => ReturnResponseError(res))
      } yield result
    }

    private def get   [T]   (token: Option[RawToken],url: URL)         (using dec: JsonDecoder[T])                     : Task[T] = exec(token, Request.get(url))
    private def post  [R, T](token: Option[RawToken], url: URL, req: R)(using dec: JsonDecoder[T], enc: JsonEncoder[R]): Task[T] = exec(token, Request.post(url, Body.fromString(req.toJson)).copy(headers = applicationJson))

    override def groupByCode       (group: GroupCode)                  (using token: RawToken, app: ApplicationCode) = get[Option[RawGroup]]                                     (Some(token),  base / "app" / ApplicationCode.value(app) / "group")
    override def storeGroup(request: StoreGroupRequest)                (using token: RawToken, app: ApplicationCode) = post[StoreGroupRequest, RawGroup]                         (Some(token),  base / "app" / ApplicationCode.value(app) / "group", request)
    override def removeGroup(request: RemoveGroupRequest)              (using token: RawToken, app: ApplicationCode) = post[RemoveGroupRequest, Long]                            (Some(token),  base / "app" / ApplicationCode.value(app) / "group" / "delete", request)
    override def groups                                                (using token: RawToken, app: ApplicationCode) = get[Seq[RawGroup]]                                        (Some(token),  base / "app" / ApplicationCode.value(app) / "groups")
    override def groupsByCode      (groups: Seq[GroupCode])            (using token: RawToken, app: ApplicationCode) = get[Seq[RawGroup]]                                        (Some(token), (base / "app" / ApplicationCode.value(app) / "groups").queryParams(QueryParams(Map("code" -> Chunk.fromIterator(groups.map(GroupCode.value).iterator)))))
    override def usersByGroupByCode(group: GroupCode)                  (using token: RawToken, app: ApplicationCode) = get[Seq[RawUserEntry]]                                    (Some(token),  base / "app" / ApplicationCode.value(app) / "group" / GroupCode.value(group) / "users")
    override def storeUser(request: StoreUserRequest)                  (using token: RawToken, app: ApplicationCode) = post[StoreUserRequest, RawUserEntry]                      (Some(token),  base / "app" / ApplicationCode.value(app) / "user", request)
    override def removeUser(request: RemoveUserRequest)                (using token: RawToken, app: ApplicationCode) = post[RemoveUserRequest, Long]                             (Some(token),  base / "app" / ApplicationCode.value(app) / "user" / "delete", request)
    override def users                                                 (using token: RawToken, app: ApplicationCode) = get[Seq[RawUserEntry]]                                    (Some(token),  base / "app" / ApplicationCode.value(app) / "users")
    override def roles                                                 (using token: RawToken, app: ApplicationCode) = get[Seq[RawRole]]                                         (Some(token),  base / "app" / ApplicationCode.value(app) / "roles")
    override def passwordResetLink(request: RequestPasswordRequestLink)(using token: RawToken, app: ApplicationCode) = post[RequestPasswordRequestLink, PasswordResetLink]       (Some(token),  base / "app" / ApplicationCode.value(app) / "password" / "reset", request)
    override def setPin           (request: SetUserPin)                (using token: RawToken, app: ApplicationCode) = post[SetUserPin, Boolean]                                 (Some(token),  base / "app" / ApplicationCode.value(app) / "user" / "pin", request)
    override def validatePin      (request: ValidateUserPin)           (using token: RawToken                      ) = post[ValidateUserPin, Boolean]                            (Some(token),  base                                      / "user" / "pin" / "validate", request)
    override def emailLoginLink   (request: LoginViaEmailLinkRequest)  (using                  app: ApplicationCode) = post[LoginViaEmailLinkRequest, LoginViaEmailLinkResponse] (None       ,  base / "app" / ApplicationCode.value(app) / "login" / "email", request)

  }

}