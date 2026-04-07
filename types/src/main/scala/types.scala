package morbid.types

import zio.json.JsonCodec
import zio.json.{JsonEncoder, JsonDecoder, JsonFieldEncoder, JsonFieldDecoder}
import scala.annotation.targetName
import scala.util.matching.Regex

opaque type TenantId        = Long
opaque type AccountId       = Long
opaque type UserId          = Long
opaque type ApplicationId   = Long
opaque type ProviderId      = Long
opaque type GroupId         = Long
opaque type RoleId          = Long
opaque type PermissionId    = Long
opaque type PinId           = Long
opaque type TenantName      = String
opaque type TenantCode      = String
opaque type AccountName     = String
opaque type AccountCode     = String
opaque type ApplicationName = String
opaque type ApplicationCode = String
opaque type GroupName       = String
opaque type GroupCode       = String
opaque type RoleName        = String
opaque type RoleCode        = String
opaque type PermissionName  = String
opaque type PermissionCode  = String
opaque type ProviderName    = String
opaque type ProviderCode    = String
opaque type UserCode        = String
opaque type Email           = String
opaque type EmailUser       = String
opaque type Pin             = String
opaque type Sha256Hash      = String
opaque type Password        = String
opaque type Domain          = String
opaque type Magic           = String
opaque type Link            = String

// --- Validation helpers (inlined from guara to avoid dependency) ---

private val code      = "[a-zA-Z0-9_]+".r
private val latinName = "[À-ſ\\w.\\-&, ()'/]+".r

private def safeDecode(regex: Regex, maxLength: Int): JsonDecoder[String] = {
  JsonDecoder.string.mapOrFail { str =>
    (str.length > maxLength, regex.matches(str)) match
      case (true, _)  => Left(s"'$str' must have at most $maxLength chars")
      case (_, false) => Left(s"'$str' has invalid chars")
      case (_, true)  => Right(str.trim.replaceAll(" +", " "))
  }
}

private def safeCode      = safeDecode(code, _)
private def safeLatinName = safeDecode(latinName, _)

private val domainFrom = ".+@(.+)"       .r
private val userFrom   = "(.+)@.+"       .r
private val domainRe   = "[\\w\\.\\-]+"  .r
private val emailRe    = "[\\w\\.\\-@]+" .r

// --- OpaqueOps ---

trait OpaqueOps[N, T] {
  def of(n: N)     : T         = n.asInstanceOf[T]
  def value(t: T)  : N         = t.asInstanceOf[N]
  def option(n: N) : Option[T] = Option(n.asInstanceOf[T])
}

// --- Long-based companions ---

object TenantId extends OpaqueOps[Long, TenantId] {
  given JsonCodec[TenantId] = JsonCodec.long
}

object AccountId extends OpaqueOps[Long, AccountId] {
  given JsonCodec[AccountId] = JsonCodec.long
}

object UserId extends OpaqueOps[Long, UserId] {
  given JsonCodec[UserId] = JsonCodec.long
}

object ApplicationId extends OpaqueOps[Long, ApplicationId] {
  given JsonCodec[ApplicationId] = JsonCodec.long
}

object ProviderId extends OpaqueOps[Long, ProviderId] {
  given JsonCodec[ProviderId] = JsonCodec.long
}

object GroupId extends OpaqueOps[Long, GroupId] {
  given JsonCodec[GroupId] = JsonCodec.long
}

object RoleId extends OpaqueOps[Long, RoleId] {
  given JsonCodec[RoleId] = JsonCodec.long
}

object PermissionId extends OpaqueOps[Long, PermissionId] {
  given JsonCodec[PermissionId] = JsonCodec.long
}

object PinId extends OpaqueOps[Long, PinId]

// --- String-based companions ---

object TenantName extends OpaqueOps[String, TenantName] {
  given JsonEncoder[TenantName] = JsonEncoder.string
  given JsonDecoder[TenantName] = safeLatinName(128)
}

object TenantCode extends OpaqueOps[String, TenantCode] {
  val DEFAULT = TenantCode.of("DEFAULT")
  given JsonEncoder[TenantCode] = JsonEncoder.string
  given JsonDecoder[TenantCode] = safeCode(64)
}

object AccountName extends OpaqueOps[String, AccountName] {
  given JsonEncoder[AccountName] = JsonEncoder.string
  given JsonDecoder[AccountName] = safeLatinName(64)
}

object AccountCode extends OpaqueOps[String, AccountCode] {
  given JsonEncoder[AccountCode] = JsonEncoder.string
  given JsonDecoder[AccountCode] = safeCode(16)
}

object ApplicationName extends OpaqueOps[String, ApplicationName] {
  given JsonEncoder[ApplicationName]      = JsonEncoder.string
  given JsonDecoder[ApplicationName]      = safeLatinName(256)
  given JsonFieldEncoder[ApplicationName] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationName] = JsonFieldDecoder.string
}

object ApplicationCode extends OpaqueOps[String, ApplicationCode] {
  given JsonEncoder[ApplicationCode]      = JsonEncoder.string
  given JsonDecoder[ApplicationCode]      = safeCode(16)
  given JsonFieldEncoder[ApplicationCode] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationCode] = JsonFieldDecoder.string
}

object GroupName extends OpaqueOps[String, GroupName] {
  given JsonEncoder[GroupName] = JsonEncoder.string
  given JsonDecoder[GroupName] = safeLatinName(64)
}

object GroupCode extends OpaqueOps[String, GroupCode] {
  def all   = GroupCode.of("all")
  def admin = GroupCode.of("admin")
  given JsonEncoder[GroupCode] = JsonEncoder.string
  given JsonDecoder[GroupCode] = safeCode(16)
}

object RoleName extends OpaqueOps[String, RoleName] {
  given JsonEncoder[RoleName]      = JsonEncoder.string
  given JsonDecoder[RoleName]      = safeLatinName(32)
  given JsonFieldEncoder[RoleName] = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleName] = JsonFieldDecoder.string
}

object RoleCode extends OpaqueOps[String, RoleCode] {
  given JsonEncoder[RoleCode]      = JsonEncoder.string
  given JsonDecoder[RoleCode]      = safeCode(16)
  given JsonFieldEncoder[RoleCode] = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleCode] = JsonFieldDecoder.string
}

object PermissionName extends OpaqueOps[String, PermissionName] {
  given JsonEncoder[PermissionName] = JsonEncoder.string
  given JsonDecoder[PermissionName] = safeLatinName(128)
}

object PermissionCode extends OpaqueOps[String, PermissionCode] {
  given JsonEncoder[PermissionCode] = JsonEncoder.string
  given JsonDecoder[PermissionCode] = safeCode(16)
}

object ProviderName extends OpaqueOps[String, ProviderName] {
  given JsonEncoder[ProviderName] = JsonEncoder.string
  given JsonDecoder[ProviderName] = safeLatinName(256)
}

object ProviderCode extends OpaqueOps[String, ProviderCode] {
  given JsonEncoder[ProviderCode] = JsonEncoder.string
  given JsonDecoder[ProviderCode] = safeCode(128)
}

object UserCode extends OpaqueOps[String, UserCode] {
  given JsonEncoder[UserCode] = JsonEncoder.string
  given JsonDecoder[UserCode] = safeCode(128)
}

object Email extends OpaqueOps[String, Email] {
  given JsonEncoder[Email] = JsonEncoder.string
  given JsonDecoder[Email] = safeDecode(emailRe, 256)
}

object EmailUser extends OpaqueOps[String, EmailUser]

object Pin extends OpaqueOps[String, Pin] {
  given JsonEncoder[Pin] = JsonEncoder.string
  given JsonDecoder[Pin] = JsonDecoder.string
}

object Sha256Hash extends OpaqueOps[String, Sha256Hash]

object Password extends OpaqueOps[String, Password] {
  given JsonCodec[Password] = JsonCodec.string
}

object Domain extends OpaqueOps[String, Domain] {
  given JsonEncoder[Domain] = JsonEncoder.string
  given JsonDecoder[Domain] = safeDecode(domainRe, 256)
}

object Magic extends OpaqueOps[String, Magic] {
  given JsonEncoder[Magic] = JsonEncoder.string
  given JsonDecoder[Magic] = JsonDecoder.string
}

object Link extends OpaqueOps[String, Link] {
  given JsonEncoder[Link] = JsonEncoder.string
  given JsonDecoder[Link] = JsonDecoder.string
}

// --- Extensions ---

extension (it: Email) {
  def domainName: Option[Domain] =
    it match {
      case domainFrom(value) => Some(Domain.of(value))
      case _                 => None
    }

  def userName: Option[EmailUser] =
    it match {
      case userFrom(value) => Some(EmailUser.of(value))
      case _ => None
    }

  def toLowerCase: Email = it.toLowerCase
}

extension (it: Password) {
  def isValid = it.trim.length >= 6
}

extension (it: Magic) {
  @targetName("magic") def string: String = it
  def is(value: String): Boolean = it == value
}
