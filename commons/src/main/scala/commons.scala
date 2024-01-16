package morbid

object types {

  import guara.utils.{safeCode, safeName, safeDecode}
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
  opaque type Pin             = String
  opaque type Sha256Hash      = String
  opaque type Password        = String
  opaque type Domain          = String
  opaque type Magic           = String

  given JsonCodec[TenantId]      = JsonCodec.long
  given JsonCodec[AccountId]     = JsonCodec.long
  given JsonCodec[UserId]        = JsonCodec.long
  given JsonCodec[ApplicationId] = JsonCodec.long
  given JsonCodec[GroupId]       = JsonCodec.long
  given JsonCodec[RoleId]        = JsonCodec.long
  given JsonCodec[PermissionId]  = JsonCodec.long
  given JsonCodec[ProviderId]    = JsonCodec.long

  // w = [a-zA-Z_0-9]

  private val domainFrom = ".+@(.+)"       .r
  private val domain     = "[\\w\\.\\-]+"  .r
  private val email      = "[\\w\\.\\-@]+" .r

  given JsonEncoder      [TenantName]      = JsonEncoder.string
  given JsonEncoder      [TenantCode]      = JsonEncoder.string
  given JsonEncoder      [AccountName]     = JsonEncoder.string
  given JsonEncoder      [AccountCode]     = JsonEncoder.string
  given JsonEncoder      [ApplicationName] = JsonEncoder.string
  given JsonEncoder      [ApplicationCode] = JsonEncoder.string
  given JsonEncoder      [GroupName]       = JsonEncoder.string
  given JsonEncoder      [GroupCode]       = JsonEncoder.string
  given JsonEncoder      [RoleName]        = JsonEncoder.string
  given JsonEncoder      [RoleCode]        = JsonEncoder.string
  given JsonEncoder      [PermissionName]  = JsonEncoder.string
  given JsonEncoder      [PermissionCode]  = JsonEncoder.string
  given JsonEncoder      [ProviderName]    = JsonEncoder.string
  given JsonEncoder      [ProviderCode]    = JsonEncoder.string
  given JsonEncoder      [UserCode]        = JsonEncoder.string
  given JsonEncoder      [Email]           = JsonEncoder.string
  given JsonEncoder      [Domain]          = JsonEncoder.string
  given JsonEncoder      [Magic]           = JsonEncoder.string
  given JsonEncoder      [Pin]             = JsonEncoder.string

  given JsonDecoder      [TenantName]      = safeName(128)
  given JsonDecoder      [AccountName]     = safeName(64)
  given JsonDecoder      [ApplicationName] = safeName(256)
  given JsonDecoder      [GroupName]       = safeName(64)
  given JsonDecoder      [RoleName]        = safeName(32)
  given JsonDecoder      [PermissionName]  = safeName(128)
  given JsonDecoder      [ProviderName]    = safeName(256)

  given JsonDecoder      [TenantCode]      = safeCode(64)
  given JsonDecoder      [AccountCode]     = safeCode(16)
  given JsonDecoder      [ApplicationCode] = safeCode(16)
  given JsonDecoder      [GroupCode]       = safeCode(16)
  given JsonDecoder      [UserCode]        = safeCode(128)
  given JsonDecoder      [RoleCode]        = safeCode(16)
  given JsonDecoder      [PermissionCode]  = safeCode(16)
  given JsonDecoder      [ProviderCode]    = safeCode(128)

  given JsonDecoder      [Email]           = safeDecode(email, 256)
  given JsonDecoder      [Domain]          = safeDecode(domain, 256)
  given JsonDecoder      [Magic]           = JsonDecoder.string
  given JsonDecoder      [Password]        = JsonDecoder.string
  given JsonDecoder      [Pin]             = JsonDecoder.string

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
  object GroupCode       extends OpaqueOps[String, GroupCode]
  object GroupId         extends OpaqueOps[Long, GroupId]
  object GroupName       extends OpaqueOps[String, GroupName]
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
  object TenantCode      extends OpaqueOps[String, TenantCode]
  object TenantId        extends OpaqueOps[Long, TenantId]
  object TenantName      extends OpaqueOps[String, TenantName]
  object UserCode        extends OpaqueOps[String, UserCode]
  object UserId          extends OpaqueOps[Long, UserId]

  extension (it: Email) {
    def domainName: Option[Domain] = {
      it match {
        case domainFrom(value) => Some(Domain.of(value))
        case _                 => None
      }
    }
  }

  extension (it: Magic) {
    @targetName("magic") def string: String = it
    def is(value: String): Boolean = it == value
  }
}

object domain {

  import types.*
  import zio.json.*
  import zio.optics.Lens
  import zio.json.internal.Write
  import java.time.{LocalDateTime, ZonedDateTime}

  enum UserKind {
    case RE /* Regular */ ,
         SA /* Service Account */
  }

  enum ProviderKind {
    case UP   /* Username and Password */ ,
         SAML /* SAML */
  }

  given JsonEncoder[UserKind]     = (kind: UserKind    , indent: Option[Int], out: Write) => out.write(s"\"${kind.toString}\"")
  given JsonEncoder[ProviderKind] = (kind: ProviderKind, indent: Option[Int], out: Write) => out.write(s"\"${kind.toString}\"")

  given JsonDecoder[UserKind]     = JsonDecoder[String](using JsonDecoder.string).map(UserKind.valueOf)
  given JsonDecoder[ProviderKind] = JsonDecoder[String](using JsonDecoder.string).map(ProviderKind.valueOf)

  object raw {

    case class RawAccount(
      id         : AccountId,
      created    : LocalDateTime,
      deleted    : Option[LocalDateTime],
      tenant     : TenantId,
      tenantCode : TenantCode,
      active     : Boolean,
      code       : AccountCode,
      name       : AccountName,
    )

    case class RawUserEntry(
      id      : UserId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      account : AccountId,
      kind    : Option[UserKind],
      code    : UserCode,
      active  : Boolean,
      email   : Email
    )

    case class RawUser(
      details      : RawUserDetails,
      applications : Seq[RawApplication] = Seq.empty
    )

    case class RawUserDetails(
      id          : UserId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime] = None,
      tenant      : TenantId,
      tenantCode  : TenantCode,
      account     : AccountId,
      accountCode : AccountCode,
      kind        : Option[UserKind] = None,
      active      : Boolean,
      code        : UserCode,
      email       : Email
    )

    case class RawApplicationDetails(
      id      : ApplicationId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      active  : Boolean,
      code    : ApplicationCode,
      name    : ApplicationName,
    )

    case class RawApplication(
      details : RawApplicationDetails,
      groups  : Seq[RawGroup] = Seq.empty,
      roles   : Seq[RawRole]  = Seq.empty
    )

    case class RawIdentityProvider(
      id       : ProviderId,
      created  : LocalDateTime,
      deleted  : Option[LocalDateTime],
      account  : AccountId,
      active   : Boolean,
      domain   : Domain,
      kind     : ProviderKind, //SAML, UP, etc
      code     : ProviderCode,
      name     : ProviderName,
    )

    case class RawGroup(
      id      : GroupId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      code    : GroupCode,
      name    : GroupName,
    )

    case class RawPermission(
      id      : PermissionId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      code    : PermissionCode,
      name    : PermissionName,
    )

    case class RawRole(
      id          : RoleId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime],
      code        : RoleCode,
      name        : RoleName,
      permissions : Seq[RawPermission] = Seq.empty
    )

    val userDetailsLens = Lens[RawUser, RawUserDetails](
      get = user => Right(user.details),
      set = details => user => Right(user.copy(details = details))
    )

    val idLens = Lens[RawUserDetails, UserId](
      get = details => Right(details.id),
      set = id => details => Right(details.copy(id = id))
    )

    given JsonEncoder[RawApplicationDetails] = DeriveJsonEncoder.gen[RawApplicationDetails]
    given JsonDecoder[RawApplicationDetails] = DeriveJsonDecoder.gen[RawApplicationDetails]
    given JsonEncoder[RawApplication]        = DeriveJsonEncoder.gen[RawApplication]
    given JsonDecoder[RawApplication]        = DeriveJsonDecoder.gen[RawApplication]
    given JsonEncoder[RawUserDetails]        = DeriveJsonEncoder.gen[RawUserDetails]
    given JsonDecoder[RawUserDetails]        = DeriveJsonDecoder.gen[RawUserDetails]
    given JsonEncoder[RawGroup]              = DeriveJsonEncoder.gen[RawGroup]
    given JsonDecoder[RawGroup]              = DeriveJsonDecoder.gen[RawGroup]
    given JsonEncoder[RawPermission]         = DeriveJsonEncoder.gen[RawPermission]
    given JsonDecoder[RawPermission]         = DeriveJsonDecoder.gen[RawPermission]
    given JsonEncoder[RawRole]               = DeriveJsonEncoder.gen[RawRole]
    given JsonDecoder[RawRole]               = DeriveJsonDecoder.gen[RawRole]
    given JsonEncoder[RawUser]               = DeriveJsonEncoder.gen[RawUser]
    given JsonDecoder[RawUser]               = DeriveJsonDecoder.gen[RawUser]
    given JsonEncoder[RawUserEntry]          = DeriveJsonEncoder.gen[RawUserEntry]
    given JsonDecoder[RawUserEntry]          = DeriveJsonDecoder.gen[RawUserEntry]
    given JsonEncoder[RawIdentityProvider]   = DeriveJsonEncoder.gen[RawIdentityProvider]
    given JsonDecoder[RawIdentityProvider]   = DeriveJsonDecoder.gen[RawIdentityProvider]
  }

  object simple {

    import raw.*

    case class SimplePermission (id: PermissionId, code: PermissionCode, name: PermissionName)
    case class SimpleRole       (id: RoleId      , code: RoleCode      , name: RoleName, permissions: Seq[SimplePermission])
    case class SimpleGroup      (id: GroupId     , code: GroupCode     , name: GroupName)

    case class SimpleApp(
     id     : ApplicationId,
     code   : ApplicationCode,
     name   : ApplicationName,
     groups : Seq[SimpleGroup],
     roles  : Seq[SimpleRole]
    )

    case class SimpleTenant (id: TenantId, code: TenantCode)
    case class SimpleAccount(id: AccountId, code: AccountCode)

    case class SimpleUser(
      tenant       : SimpleTenant,
      account      : SimpleAccount,
      id           : UserId,
      code         : UserCode,
      email        : Email,
      kind         : Option[UserKind],
      applications : Seq[SimpleApp]
    )

    extension (it: RawGroup)
      def simple:SimpleGroup = SimpleGroup(it.id, it.code, it.name)

    extension (it: RawPermission)
      def simple: SimplePermission = SimplePermission(it.id, it.code, it.name)

    extension (it: RawRole)
      def simple: SimpleRole = SimpleRole(it.id, it.code, it.name, it.permissions.map(_.simple))

    extension (it: RawApplication)
      def simple: SimpleApp = SimpleApp(
        id     = it.details.id,
        code   = it.details.code,
        name   = it.details.name,
        groups = it.groups.map(_.simple),
        roles  = it.roles.map(_.simple)
      )

    extension (it: RawUser)
      def simple: SimpleUser = SimpleUser(
        tenant       = SimpleTenant(it.details.tenant, it.details.tenantCode),
        account      = SimpleAccount(it.details.account, it.details.accountCode),
        id           = it.details.id,
        code         = it.details.code,
        email        = it.details.email,
        kind         = it.details.kind,
        applications = it.applications.map(_.simple)
      )

    given JsonEncoder[SimplePermission] = DeriveJsonEncoder.gen[SimplePermission]
    given JsonEncoder[SimpleRole]       = DeriveJsonEncoder.gen[SimpleRole]
    given JsonEncoder[SimpleGroup]      = DeriveJsonEncoder.gen[SimpleGroup]
    given JsonEncoder[SimpleApp]        = DeriveJsonEncoder.gen[SimpleApp]
    given JsonEncoder[SimpleAccount]    = DeriveJsonEncoder.gen[SimpleAccount]
    given JsonEncoder[SimpleTenant]     = DeriveJsonEncoder.gen[SimpleTenant]
    given JsonEncoder[SimpleUser]       = DeriveJsonEncoder.gen[SimpleUser]
  }

  object mini {

    import raw.*

    case class MiniApp(
      groups : Seq[GroupCode],
      roles  : Map[RoleCode, Seq[PermissionCode]]
    )

    case class MiniUser(
      tenant       : TenantCode,
      account      : AccountCode,
      code         : UserCode,
      email        : Email,
      kind         : Option[UserKind],
      applications : Map[ApplicationCode, MiniApp]
    )

    extension (it: RawApplication)
      def mini: MiniApp = MiniApp(
        groups = it.groups.map(_.code),
        roles  = it.roles.map { role => role.code -> role.permissions.map(_.code) }.toMap
      )

    extension (it: RawUser)
      def mini: MiniUser = MiniUser(
        tenant       = it.details.tenantCode,
        account      = it.details.accountCode,
        code         = it.details.code,
        email        = it.details.email,
        kind         = it.details.kind,
        applications = it.applications.map { app => app.details.code -> app.mini }.toMap
      )

    given JsonEncoder[MiniApp]  = DeriveJsonEncoder.gen[MiniApp]
    given JsonDecoder[MiniApp]  = DeriveJsonDecoder.gen[MiniApp]
    given JsonEncoder[MiniUser] = DeriveJsonEncoder.gen[MiniUser]
    given JsonDecoder[MiniUser] = DeriveJsonDecoder.gen[MiniUser]
  }

  object token {

    import raw.*

    opaque type RawToken = String

    object RawToken:
      def of(value: String): RawToken = value

    extension (it: RawToken)
      def string: String = it

    case class Token(
      created : ZonedDateTime,
      expires : Option[ZonedDateTime],
      user    : RawUser
    ) {
      def roleByCode(code: RoleCode)(using app: ApplicationCode): Option[RawRole] = {
        for {
          a <- user.applications.find(_.details.code == app)
          r <- a.roles.find(_.code == code)
        } yield r
      }

      def hasRole(code: RoleCode)(using app: ApplicationCode) = roleByCode(code).isDefined
    }

    given JsonEncoder[Token] = DeriveJsonEncoder.gen[Token]
    given JsonDecoder[Token] = DeriveJsonDecoder.gen[Token]

  }
}
