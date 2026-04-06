package morbid

object proto {

  import zio.json.*
  import types.*

  case class VerifyGoogleTokenRequest(token: JwtToken) derives JsonCodec
  case class VerifyMorbidTokenRequest(token: JwtToken) derives JsonCodec
  case class SetClaimsRequest(uid: String, claims: Map[String, String]) derives JsonCodec
  case class GetLoginMode(email: Email, tenant: Option[TenantCode]) derives JsonCodec
  case class EmitToken(email: Email, magic: Magic, days: Option[Int]) derives JsonCodec
}
