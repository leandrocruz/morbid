package morbid.proto

import morbid.types.*
import zio.*
import zio.json.*

case class VerifyGoogleTokenRequest(token: String)
case class VerifyMorbidTokenRequest(token: String)
case class SetClaimsRequest(uid: String, claims: Map[String, String])
case class GetLoginMode(email: Email, tenant: Option[TenantCode])
case class EmitToken(email: Email, magic: Magic, days: Option[Int]) derives JsonCodec

given JsonDecoder[VerifyGoogleTokenRequest] = DeriveJsonDecoder.gen
given JsonDecoder[VerifyMorbidTokenRequest] = DeriveJsonDecoder.gen
given JsonDecoder[SetClaimsRequest]         = DeriveJsonDecoder.gen
given JsonDecoder[GetLoginMode]             = DeriveJsonDecoder.gen