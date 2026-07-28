package morbid

object proto {

  import zio.json.*
  import types.*

  case class VerifyGoogleTokenRequest(token: String)
  case class VerifyMorbidTokenRequest(token: String)
  case class SetClaimsRequest(uid: String, claims: Map[String, String])
  case class GetLoginMode(email: Email, tenant: Option[TenantCode])
  case class EmitToken(email: Email, magic: Magic, days: Option[Int])
  case class SwapTokenRequest(token: String, magic: Magic)

  given JsonCodec[VerifyGoogleTokenRequest] = DeriveJsonCodec.gen
  given JsonCodec[VerifyMorbidTokenRequest] = DeriveJsonCodec.gen
  given JsonCodec[SetClaimsRequest]         = DeriveJsonCodec.gen
  given JsonCodec[GetLoginMode]             = DeriveJsonCodec.gen
  given JsonCodec[EmitToken]                = DeriveJsonCodec.gen
  given JsonCodec[SwapTokenRequest]         = DeriveJsonCodec.gen
}