package morbid

import zio.*

object client {

  import morbid.types.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.domain.token.{Token, RawToken}
  import guara.utils.parse
  import zio.http.*
  import zio.json.*
  import scala.annotation.targetName
  import java.time.ZonedDateTime

  trait MorbidClient {
    def proxy(request: Request): Task[Response]
    def tokenFrom(token: RawToken): Task[Token]
    def groups                                    (using token: RawToken): Task[Seq[RawGroup]]
    def groupsByCode      (groups: Seq[GroupCode])(using token: RawToken): Task[Seq[RawGroup]]
    def groupByCode       (group: GroupCode)      (using token: RawToken): Task[Option[RawGroup]]
    def usersByGroupByCode(group: GroupCode)      (using token: RawToken): Task[Seq[RawUserEntry]]
    def roles                                     (using token: RawToken): Task[Seq[RawRole]]
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

    private val appCode = "presto"
    private val headers = Headers(Chunk(Header.Custom("X-Oystr-Service", "PrestoApi")))
    private val applicationJson = Headers(Chunk(Header.ContentType(MediaType("application", "json"))))

    override def proxy(request: Request): Task[Response] = {
      for {
        resp <- client.request(request.copy(url = base ++ request.url)).provideSome(ZLayer.succeed(scope))
      } yield resp.copy(headers = resp.headers ++ headers)
    }

    override def tokenFrom(token: RawToken): Task[Token] = {
      val req = Request.post(base / "verify", Body.fromString(s"""{"token":"$token"}""")).copy(headers = applicationJson ++ headers)
      for {
        res    <- client.request(req).provideSome(ZLayer.succeed(scope))
        result <- res.body.parse[Token]
      } yield result
    }

    private def request[T](url: URL)(using token: RawToken, dec: JsonDecoder[T]): Task[T] = {
      val req = Request.get(url).copy(headers = headers.addHeader(Header.Custom("X-MorbidToken", token.string)))
      for {
        _      <- ZIO.log(s"Calling '${url.encode}'")
        res    <- client.request(req).provideSome(ZLayer.succeed(scope))
        result <- res.body.parse[T]
      } yield result
    }

    override def groupByCode       (group: GroupCode)       (using token: RawToken): Task[Option[RawGroup]]  = request[Option[RawGroup]]  (base / "app" / appCode / "group")
    override def groups                                     (using token: RawToken): Task[Seq[RawGroup]]     = request[Seq[RawGroup]]     (base / "app" / appCode / "groups")
    override def groupsByCode      (groups: Seq[GroupCode]) (using token: RawToken): Task[Seq[RawGroup]]     = request[Seq[RawGroup]]    ((base / "app" / appCode / "groups").queryParams(QueryParams(Map("code" -> Chunk.fromIterator(groups.map(GroupCode.value).iterator)))))
    override def usersByGroupByCode(group: GroupCode)       (using token: RawToken): Task[Seq[RawUserEntry]] = request[Seq[RawUserEntry]] (base / "app" / appCode / "group" / GroupCode.value(group) / "users")
    override def roles                                      (using token: RawToken): Task[Seq[RawRole]]      = request[Seq[RawRole]]      (base / "app" / appCode / "roles")
  }
}