package morbid

import zio.*

object config {

  import zio.config.*
  import zio.config.magnolia.*
  import zio.config.typesafe.*
  import Config.*

  case class JwtConfig(key: String)
  case class IdentityConfig(key: String, database: String)
  case class ClockConfig(timezone: String)
  case class MagicConfig(password: String)
  case class PinConfig(prefix: String)
  case class MorbidConfig(identities: IdentityConfig, jwt: JwtConfig, clock: ClockConfig, magic: MagicConfig, pin: PinConfig)

  object MorbidConfig {
    val layer = ZLayer {
      TypesafeConfigProvider.fromResourcePath(enableCommaSeparatedValueAsList = true).load(deriveConfig[MorbidConfig])
    }
  }

}

object utils {

  import zio.json.*
  import domain.raw.RawUser
  import domain.simple.*
  import domain.mini.*
  import types.ApplicationCode

  val Morbid = ApplicationCode.of("morbid")

  extension (user: RawUser)
    def asJson(format: Option[String]): String = {
      format match {
        case Some("simple") => user.simple.toJson
        case Some("mini")   => user.mini.toJson
        case _              => user.toJson
      }
    }
}

object proto {

  import zio.json.*
  import types.*
  import domain.UserKind

  case class VerifyGoogleTokenRequest(token: String)
  case class VerifyMorbidTokenRequest(token: String)
  case class ImpersonationRequest(email: Email, magic: Magic)
  case class SetClaimsRequest(uid: String, claims: Map[String, String])
  case class GetLoginMode(email: Email, tenant: Option[TenantCode])
  case class CreateUserRequest(email: Email, code: Option[UserCode] = None, password: Option[Password] = None, tenant: Option[TenantCode] = None, kind: Option[UserKind] = None,                       groups: Seq[GroupCode] = Seq.empty)
  case class CreateUser       (email: Email, code: UserCode,                password: Password,                tenant: Option[TenantCode] = None, kind: Option[UserKind] = None, account: AccountCode, groups: Seq[GroupCode] = Seq.empty)
  case class SetUserPin     (pin: Pin)
  case class ValidateUserPin(pin: Pin)

  given JsonDecoder[ImpersonationRequest]     = DeriveJsonDecoder.gen[ImpersonationRequest]
  given JsonDecoder[VerifyGoogleTokenRequest] = DeriveJsonDecoder.gen[VerifyGoogleTokenRequest]
  given JsonDecoder[VerifyMorbidTokenRequest] = DeriveJsonDecoder.gen[VerifyMorbidTokenRequest]
  given JsonDecoder[SetClaimsRequest]         = DeriveJsonDecoder.gen[SetClaimsRequest]
  given JsonDecoder[GetLoginMode]             = DeriveJsonDecoder.gen[GetLoginMode]
  given JsonDecoder[CreateUserRequest]        = DeriveJsonDecoder.gen[CreateUserRequest]
  given JsonDecoder[SetUserPin]               = DeriveJsonDecoder.gen[SetUserPin]
  given JsonDecoder[ValidateUserPin]          = DeriveJsonDecoder.gen[ValidateUserPin]
}

object passwords {

  import types.Password
  import scala.util.Random

  trait PasswordGenerator {
    def generate: Task[Password]
  }

  private case class DefaultPasswordGenerator() extends PasswordGenerator {
    override def generate: Task[Password] =
      ZIO.attempt {
        Password.of {
          Random.alphanumeric.take(12).mkString("")
        }
      }
  }

  object PasswordGenerator {
    val layer: ZLayer[Any, Nothing, PasswordGenerator] = ZLayer.fromFunction(DefaultPasswordGenerator.apply _)
  }

}