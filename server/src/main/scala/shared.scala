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
  case class MorbidConfig(identities: IdentityConfig, jwt: JwtConfig, clock: ClockConfig, magic: MagicConfig)

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

  case class VerifyGoogleTokenRequest(token: String)
  case class VerifyMorbidTokenRequest(token: String)
  case class ImpersonationRequest(email: Email, magic: Magic)
  case class SetClaimsRequest(uid: String, claims: Map[String, String])
  case class GetLoginMode(email: Email, tenant: Option[TenantCode])

  given JsonDecoder[ImpersonationRequest]     = DeriveJsonDecoder.gen[ImpersonationRequest]
  given JsonDecoder[VerifyGoogleTokenRequest] = DeriveJsonDecoder.gen[VerifyGoogleTokenRequest]
  given JsonDecoder[VerifyMorbidTokenRequest] = DeriveJsonDecoder.gen[VerifyMorbidTokenRequest]
  given JsonDecoder[SetClaimsRequest]         = DeriveJsonDecoder.gen[SetClaimsRequest]
  given JsonDecoder[GetLoginMode]             = DeriveJsonDecoder.gen[GetLoginMode]
}