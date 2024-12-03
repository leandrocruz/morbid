package morbid

object legacy {

  import guara.utils.parse
  import morbid.types.{AccountId, AccountName, Email, UserId}
  import zio.*
  import zio.http.*
  import zio.json.*

  import java.time.LocalDateTime

  case class LegacyToken(token: String)
  case class LegacyAccount(id: AccountId)
  case class LegacyUser(id: UserId, email: Email, account: LegacyAccount)

  case class CreateLegacyUserRequest(
    account  : AccountId,
    name     : String,
    email    : Email,
    `type`   : String,
    password : Option[String] = None
  ) //matches legacy morbid CreateUserRequest

  case class CreateLegacyAccountRequest(
    name   : AccountName,
    `type` : String
  ) //matches legacy morbid CreateUserRequest

  case class LegacyAccountResponse(
    id      : AccountId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    active  : Boolean,
    name    : AccountName,
    `type`  : String
  )

  case class LegacyClientConfig(url: String)

  object LegacyMorbid {
    val layer = ZLayer {
      for {
        cfg    <- ZIO.service[LegacyClientConfig]
        url    <- ZIO.fromEither(URL.decode(cfg.url))
        client <- ZIO.service[Client]
        scope  <- ZIO.service[Scope]
      } yield LegacyMorbidImpl(url, client, scope)
    }
  }

  trait LegacyMorbid {
    def userBy       (email: Email)                        : Task[Option[LegacyUser]]
    def create       (request: CreateLegacyUserRequest)    : Task[LegacyUser]
    def createAccount(request: CreateLegacyAccountRequest) : Task[LegacyAccountResponse]
  }

  case class LegacyMorbidImpl(url: URL, client: Client, scope: Scope) extends LegacyMorbid {

    private val headers = Headers(Header.ContentType(MediaType.application.json))

    override def userBy(email: Email): Task[Option[LegacyUser]] = {

      val result = for {
        response <- client.url(url).get(s"/user/email/$email").provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match {
                      case 404  => ZIO.succeed(None)
                      case 200  => response.body.parse[LegacyUser].map(Some(_)).mapError(err => Exception("Error parsing LegacyUser from body", err))
                      case code => ZIO.fail(Exception(s"Result code from legacy is $code"))
                    }
      } yield user

      result.mapError(err => Exception(s"Error retrieving legacy user '$email': ${err.getMessage}", err))
    }

    override def create(request: CreateLegacyUserRequest): Task[LegacyUser] = {

      val result = for {
        body     <- ZIO.attempt(Body.fromString(request.toJson))
        response <- client.url(url).addHeaders(headers).post("/user")(body).provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match {
          case 200  => response.body.parse[LegacyUser].mapError(err => Exception("Error parsing LegacyUser from body", err))
          case code => ZIO.fail(Exception(s"Result code from legacy is $code"))
        }
      } yield user

      result.mapError(err => Exception(s"Error creating user '${request.email}' for account '${request.account}'", err))
    }

    override def createAccount(request: CreateLegacyAccountRequest): Task[LegacyAccountResponse] = {

      val result = for {
        body     <- ZIO.attempt(Body.fromString(request.toJson))
        response <- client.url(url).addHeaders(headers).post("/account")(body).provideSome(ZLayer.succeed(scope))
        account  <- response.status.code match {
          case 200 => response.body.parse[LegacyAccountResponse].mapError(err => Exception("Error parsing LegacyAccountResponse from body", err))
          case code => ZIO.fail(Exception(s"Result code from legacy is $code"))
        }
      } yield account

      result.mapError(err => Exception(s"Error creating legacy account '${request.name}'", err))
    }
  }

  given JsonCodec[LegacyAccount]              = DeriveJsonCodec.gen
  given JsonCodec[LegacyUser]                 = DeriveJsonCodec.gen
  given JsonCodec[LegacyToken]                = DeriveJsonCodec.gen
  given JsonCodec[CreateLegacyUserRequest]    = DeriveJsonCodec.gen
  given JsonCodec[CreateLegacyAccountRequest] = DeriveJsonCodec.gen
  given JsonCodec[LegacyAccountResponse]      = DeriveJsonCodec.gen

}