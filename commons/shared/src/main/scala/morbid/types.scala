package morbid

object types {

  import zio.json.JsonCodec
  import zio.json.{JsonEncoder, JsonDecoder, JsonFieldEncoder, JsonFieldDecoder}
  import scala.annotation.targetName

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

  given JsonCodec[TenantId]      = JsonCodec.long
  given JsonCodec[AccountId]     = JsonCodec.long
  given JsonCodec[UserId]        = JsonCodec.long
  given JsonCodec[ApplicationId] = JsonCodec.long
  given JsonCodec[GroupId]       = JsonCodec.long
  given JsonCodec[RoleId]        = JsonCodec.long
  given JsonCodec[PermissionId]  = JsonCodec.long
  given JsonCodec[ProviderId]    = JsonCodec.long
  given JsonCodec[Password]      = JsonCodec.string

  given JsonEncoder[TenantName]      = JsonEncoder.string
  given JsonEncoder[TenantCode]      = JsonEncoder.string
  given JsonEncoder[AccountName]     = JsonEncoder.string
  given JsonEncoder[AccountCode]     = JsonEncoder.string
  given JsonEncoder[ApplicationName] = JsonEncoder.string
  given JsonEncoder[ApplicationCode] = JsonEncoder.string
  given JsonEncoder[GroupName]       = JsonEncoder.string
  given JsonEncoder[GroupCode]       = JsonEncoder.string
  given JsonEncoder[RoleName]        = JsonEncoder.string
  given JsonEncoder[RoleCode]        = JsonEncoder.string
  given JsonEncoder[PermissionName]  = JsonEncoder.string
  given JsonEncoder[PermissionCode]  = JsonEncoder.string
  given JsonEncoder[ProviderName]    = JsonEncoder.string
  given JsonEncoder[ProviderCode]    = JsonEncoder.string
  given JsonEncoder[UserCode]        = JsonEncoder.string
  given JsonEncoder[Email]           = JsonEncoder.string
  given JsonEncoder[Domain]          = JsonEncoder.string
  given JsonEncoder[Magic]           = JsonEncoder.string
  given JsonEncoder[Pin]             = JsonEncoder.string
  given JsonEncoder[Link]            = JsonEncoder.string

  // Simple decoders for shared (JS + JVM). JVM overrides these with validation in morbid.validation.
  given JsonDecoder[TenantName]      = JsonDecoder.string
  given JsonDecoder[TenantCode]      = JsonDecoder.string
  given JsonDecoder[AccountName]     = JsonDecoder.string
  given JsonDecoder[AccountCode]     = JsonDecoder.string
  given JsonDecoder[ApplicationName] = JsonDecoder.string
  given JsonDecoder[ApplicationCode] = JsonDecoder.string
  given JsonDecoder[GroupName]       = JsonDecoder.string
  given JsonDecoder[GroupCode]       = JsonDecoder.string
  given JsonDecoder[UserCode]        = JsonDecoder.string
  given JsonDecoder[RoleName]        = JsonDecoder.string
  given JsonDecoder[RoleCode]        = JsonDecoder.string
  given JsonDecoder[PermissionName]  = JsonDecoder.string
  given JsonDecoder[PermissionCode]  = JsonDecoder.string
  given JsonDecoder[ProviderName]    = JsonDecoder.string
  given JsonDecoder[ProviderCode]    = JsonDecoder.string
  given JsonDecoder[Email]           = JsonDecoder.string
  given JsonDecoder[Domain]          = JsonDecoder.string
  given JsonDecoder[Magic]           = JsonDecoder.string
  given JsonDecoder[Pin]             = JsonDecoder.string
  given JsonDecoder[Link]            = JsonDecoder.string

  given JsonFieldEncoder[ApplicationName] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationName] = JsonFieldDecoder.string
  given JsonFieldEncoder[ApplicationCode] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationCode] = JsonFieldDecoder.string
  given JsonFieldEncoder[RoleName]        = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleName]        = JsonFieldDecoder.string
  given JsonFieldEncoder[RoleCode]        = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleCode]        = JsonFieldDecoder.string

  trait OpaqueOps[N, T] {
    def of(n: N)     : T         = n.asInstanceOf[T]
    def value(t: T)  : N         = t.asInstanceOf[N]
    def option(n: N) : Option[T] = Option(n.asInstanceOf[T])
  }

  object AccountId       extends OpaqueOps[Long, AccountId]
  object AccountName     extends OpaqueOps[String, AccountName]
  object AccountCode     extends OpaqueOps[String, AccountCode]
  object ApplicationId   extends OpaqueOps[Long, ApplicationId]
  object ApplicationCode extends OpaqueOps[String, ApplicationCode]
  object ApplicationName extends OpaqueOps[String, ApplicationName]
  object Domain          extends OpaqueOps[String, Domain]
  object Email           extends OpaqueOps[String, Email]
  object EmailUser       extends OpaqueOps[String, EmailUser]
  object GroupCode       extends OpaqueOps[String, GroupCode] {
    def all   = GroupCode.of("all")
    def admin = GroupCode.of("admin")
  }
  object GroupId         extends OpaqueOps[Long, GroupId]
  object GroupName       extends OpaqueOps[String, GroupName]
  object Link            extends OpaqueOps[String, Link]
  object Magic           extends OpaqueOps[String, Magic]
  object Password        extends OpaqueOps[String, Password]
  object PinId           extends OpaqueOps[Long, PinId]
  object Pin             extends OpaqueOps[String, Pin]
  object PermissionId    extends OpaqueOps[Long, PermissionId]
  object PermissionCode  extends OpaqueOps[String, PermissionCode]
  object PermissionName  extends OpaqueOps[String, PermissionName]
  object ProviderCode    extends OpaqueOps[String, ProviderCode]
  object ProviderId      extends OpaqueOps[Long, ProviderId]
  object ProviderName    extends OpaqueOps[String, ProviderName]
  object RoleCode        extends OpaqueOps[String, RoleCode]
  object RoleId          extends OpaqueOps[Long, RoleId]
  object RoleName        extends OpaqueOps[String, RoleName]
  object Sha256Hash      extends OpaqueOps[String, Sha256Hash]
  object TenantCode      extends OpaqueOps[String, TenantCode] {
    val DEFAULT = TenantCode.of("DEFAULT")
  }
  object TenantId        extends OpaqueOps[Long, TenantId]
  object TenantName      extends OpaqueOps[String, TenantName]
  object UserCode        extends OpaqueOps[String, UserCode]
  object UserId          extends OpaqueOps[Long, UserId]

  private val domainFrom = ".+@(.+)"       .r
  private val userFrom   = "(.+)@.+"       .r

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
}
