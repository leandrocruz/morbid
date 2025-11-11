package morbid

object legacy {

  import guara.utils.parse
  import morbid.types.{AccountId, AccountName, Email, UserId}
  import zio.*
  import zio.http.*
  import zio.json.*

  case class LegacyAccount(id: AccountId, name: AccountName)
  case class LegacyToken(token: String)
  case class LegacyUser(id: UserId, email: Email, account: LegacyAccount)

  case class CreateLegacyAccountRequest(name: AccountName, `type`: String)
  case class CreateLegacyUserRequest(account: AccountId, name: String, email: Email, `type`: String, password: Option[String] = None) //matches legacy morbid CreateUserRequest

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
    def accountById  (id: AccountId)                      : Task[Option[LegacyAccount]]
    def createAccount(request: CreateLegacyAccountRequest): Task[LegacyAccount]
    def createUser   (request: CreateLegacyUserRequest)   : Task[LegacyUser]
    def userByEmail  (email: Email)                       : Task[Option[LegacyUser]]
  }

  case class LegacyMorbidImpl(url: URL, client: Client, scope: Scope) extends LegacyMorbid {

    private val headers = Headers(Header.ContentType(MediaType.application.json))

    override def userByEmail(email: Email): Task[Option[LegacyUser]] = {
      for
        response <- client.url(url).get(s"/user/email/$email").provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match
          case 404  => ZIO.succeed(None)
          case 200  => response.body.parse[LegacyUser]().map(Some(_)).mapError(err => Exception("Error parsing LegacyUser from body", err))
          case code => ZIO.fail(Exception(s"Error retrieving legacy user '$email'. Result code from legacy is $code"))
      yield user
    }

    override def accountById(id: AccountId): Task[Option[LegacyAccount]] = {
      for
        response <- client.url(url).get(s"/account/id/$id").provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match
          case 404  => ZIO.none
          case 200  => response.body.parse[LegacyAccount]().map(Some(_)).mapError(err => Exception("Error parsing LegacyAccount from body", err))
          case code => ZIO.fail(Exception(s"Error retrieving legacy account. Result code from legacy is $code"))
      yield user
    }

    override def createUser(request: CreateLegacyUserRequest): Task[LegacyUser] = {
      for
        body     <- ZIO.attempt(Body.fromString(request.toJson))
        response <- client.url(url).addHeaders(headers).post("/user")(body).provideSome(ZLayer.succeed(scope))
        user     <- response.status.code match
          case 200  => response.body.parse[LegacyUser]().mapError(err => Exception("Error parsing LegacyUser from body", err))
          case code => ZIO.fail(Exception(s"Error creating user '${request.email}' for account '${request.account}'. Result code from legacy is $code"))
      yield user
    }

    override def createAccount(request: CreateLegacyAccountRequest): Task[LegacyAccount] = {
      for
        body     <- ZIO.attempt(Body.fromString(request.toJson))
        response <- client.url(url).addHeaders(headers).post("/user")(body).provideSome(ZLayer.succeed(scope))
        account  <- response.status.code match
          case 200  => response.body.parse[LegacyAccount]().mapError(err => Exception("Error parsing LegacyUser from body", err))
          case code => ZIO.fail(Exception(s"Error creating account '${request.name}'. Result code from legacy is $code"))
      yield account
    }
  }

  given JsonCodec[LegacyAccount]              = DeriveJsonCodec.gen
  given JsonCodec[LegacyUser]                 = DeriveJsonCodec.gen
  given JsonCodec[LegacyToken]                = DeriveJsonCodec.gen
  given JsonCodec[CreateLegacyUserRequest]    = DeriveJsonCodec.gen
  given JsonCodec[CreateLegacyAccountRequest] = DeriveJsonCodec.gen

}