package morbid

object legacy {

  import morbid.types.{AccountId, Email, UserId}
  import guara.utils.parse

  import zio.*
  import zio.http.*
  import zio.json.*

  case class LegacyToken(token: String)
  case class LegacyAccount(id: AccountId)
  case class LegacyUser(id: UserId, email: Email, account: LegacyAccount)

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
    def userBy(email: Email): Task[Option[LegacyUser]]
  }

  case class LegacyMorbidImpl(url: URL, client: Client, scope: Scope) extends LegacyMorbid {

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

  }
  given JsonCodec[LegacyAccount] = DeriveJsonCodec.gen
  given JsonCodec[LegacyUser]    = DeriveJsonCodec.gen
  given JsonCodec[LegacyToken]   = DeriveJsonCodec.gen

}