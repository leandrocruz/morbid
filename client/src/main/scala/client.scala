package morbid

import zio.*

object client {

  import morbid.types.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.domain.token.{Token, RawToken}
  import morbid.domain.requests.StoreGroupRequest
  import morbid.domain.requests.given
  import guara.utils.parse
  import zio.http.*
  import zio.json.*

  trait MorbidClient {
    def proxy(request: Request): Task[Response]
    def tokenFrom(token: RawToken): Task[Token]
    def groups                                    (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupsByCode      (groups: Seq[GroupCode])(using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]
    def groupByCode       (group: GroupCode)      (using token: RawToken, app: ApplicationCode): Task[Option[RawGroup]]
    def usersByGroupByCode(group: GroupCode)      (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def users                                     (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]]
    def roles                                     (using token: RawToken, app: ApplicationCode): Task[Seq[RawRole]]
    def storeGroup(request: StoreGroupRequest)    (using token: RawToken, app: ApplicationCode): Task[RawGroup]
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

    override def tokenFrom(token: RawToken): Task[Token] = {
      val req = Request.post(base / "verify", Body.fromString(s"""{"token":"$token"}""")).copy(headers = applicationJson)
      for {
        res    <- perform(req)
        result <- res.body.parse[Token]
      } yield result
    }

    private def exec[T](req: Request)(using token: RawToken, dec: JsonDecoder[T]): Task[T] = {
      for {
        _      <- ZIO.log(s"Calling '${req.url.encode}'")
        res    <- perform(req.copy(headers = req.headers ++ morbidToken(token)))
        result <- res.body.parse[T]
      } yield result
    }

    private def get[T]    (url: URL)        (using token: RawToken, dec: JsonDecoder[T])                     : Task[T] = exec(Request.get(url))
    private def post[R, T](url: URL, req: R)(using token: RawToken, dec: JsonDecoder[T], enc: JsonEncoder[R]): Task[T] = exec(Request.post(url, Body.fromString(req.toJson)).copy(headers = applicationJson))

    override def groupByCode       (group: GroupCode)       (using token: RawToken, app: ApplicationCode): Task[Option[RawGroup]]  = get[Option[RawGroup]]             (base / "app" / ApplicationCode.value(app) / "group")
    override def storeGroup(request: StoreGroupRequest)     (using token: RawToken, app: ApplicationCode): Task[RawGroup]          = post[StoreGroupRequest, RawGroup] (base / "app" / ApplicationCode.value(app) / "group", request)
    override def groups                                     (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]     = get[Seq[RawGroup]]                (base / "app" / ApplicationCode.value(app) / "groups")
    override def groupsByCode      (groups: Seq[GroupCode]) (using token: RawToken, app: ApplicationCode): Task[Seq[RawGroup]]     = get[Seq[RawGroup]]               ((base / "app" / ApplicationCode.value(app) / "groups").queryParams(QueryParams(Map("code" -> Chunk.fromIterator(groups.map(GroupCode.value).iterator)))))
    override def usersByGroupByCode(group: GroupCode)       (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]] = get[Seq[RawUserEntry]]            (base / "app" / ApplicationCode.value(app) / "group" / GroupCode.value(group) / "users")
    override def users                                      (using token: RawToken, app: ApplicationCode): Task[Seq[RawUserEntry]] = get[Seq[RawUserEntry]]            (base / "app" / ApplicationCode.value(app) / "users")
    override def roles                                      (using token: RawToken, app: ApplicationCode): Task[Seq[RawRole]]      = get[Seq[RawRole]]                 (base / "app" / ApplicationCode.value(app) / "roles")
  }
}