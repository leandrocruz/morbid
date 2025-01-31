package morbid

object legacy {

  import morbid.types.{AccountId, Email, UserId, AccountName}
  import guara.utils.parse

  import zio.*
  import zio.http.*
  import zio.json.*

  case class LegacyToken  (token: String)
  case class LegacyAccount(id: AccountId)
  case class LegacyUser   (id: UserId, email: Email, account: LegacyAccount)

  case class CreateLegacyUserRequest   (account: AccountId, name: String, email: Email, `type`: String, password: Option[String] = None) //matches legacy morbid CreateUserRequest
  case class CreateLegacyAccountRequest(name: AccountName, `type`: String) //matches legacy morbid CreateAccountRequest

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
    def userBy             (email: Email)                       : Task[Option[LegacyUser]]
    def createLegacyUser   (request: CreateLegacyUserRequest)   : Task[LegacyUser]
    def createLegacyAccount(request: CreateLegacyAccountRequest): Task[LegacyAccount]
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

    override def createLegacyUser(request: CreateLegacyUserRequest): Task[LegacyUser] = {

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

    override def createLegacyAccount(request: CreateLegacyAccountRequest): Task[LegacyAccount] = {

      val result = for {
        body     <- ZIO.attempt(Body.fromString(request.toJson))
        response <- client.url(url).addHeaders(headers).post("/account")(body).provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match {
          case 200 => response.body.parse[LegacyAccount].mapError(err => Exception("Error parsing LegacyAccount from body", err))
          case code => ZIO.fail(Exception(s"Result code from legacy is $code"))
        }
      } yield user

      result.mapError(err => Exception(s"Error creating legacy account '${request.name}'", err))
    }

  }

  given JsonCodec[CreateLegacyAccountRequest] = DeriveJsonCodec.gen
  given JsonCodec[LegacyAccount]              = DeriveJsonCodec.gen
  given JsonCodec[LegacyUser]                 = DeriveJsonCodec.gen
  given JsonCodec[LegacyToken]                = DeriveJsonCodec.gen
  given JsonCodec[CreateLegacyUserRequest]    = DeriveJsonCodec.gen

}