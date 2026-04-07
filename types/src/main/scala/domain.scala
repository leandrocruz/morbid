package morbid.domain

import morbid.types.{*, given}
import morbid.domain.token.SingleAppUser
import zio.json.*
import zio.optics.Lens
import zio.json.internal.Write
import java.time.{LocalDateTime, ZonedDateTime}

val RootAccount = AccountId.of(1)

trait HasEmail {
  def email: Email
}

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

  import morbid.domain.token.CompactApplication
  import io.scalaland.chimney.dsl.*

  case class RawTenant(
    id   : TenantId,
    code : TenantCode,
  )

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

  case class RawUserData(
    id      : UserId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    account : AccountId,
    kind    : Option[UserKind],
    code    : UserCode,
    active  : Boolean,
    email   : Email,
    groups  : Seq[RawGroup]
  )

  case class RawUser(
    details      : RawUserDetails,
    applications : Seq[RawApplication] = Seq.empty
  ) {
    def narrowTo(application: ApplicationCode): Option[SingleAppUser] = {
      applications
        .find(_.details.code == application)
        .map(app => SingleAppUser(details, CompactApplication.of(app)))
    }
  }

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
    groups  : Seq[RawGroup] = Seq.empty
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
    roles   : Seq[RawRole] = Seq.empty
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

  given JsonCodec[RawApplicationDetails] = DeriveJsonCodec.gen
  given JsonCodec[RawApplication]        = DeriveJsonCodec.gen
  given JsonCodec[RawUserData]           = DeriveJsonCodec.gen
  given JsonCodec[RawUserDetails]        = DeriveJsonCodec.gen
  given JsonCodec[RawGroup]              = DeriveJsonCodec.gen
  given JsonCodec[RawPermission]         = DeriveJsonCodec.gen
  given JsonCodec[RawRole]               = DeriveJsonCodec.gen
  given JsonCodec[RawUser]               = DeriveJsonCodec.gen
  given JsonCodec[RawUserEntry]          = DeriveJsonCodec.gen
  given JsonCodec[RawAccount]            = DeriveJsonCodec.gen
  given JsonCodec[RawIdentityProvider]   = DeriveJsonCodec.gen
}

object token {

  import raw.*
  import io.scalaland.chimney.Transformer
  import io.scalaland.chimney.dsl.*

  opaque type RawToken = String

  object RawToken {
    def of(value: String): RawToken = value
    given JsonCodec[RawToken] = JsonCodec.string
  }

  extension (it: RawToken)
    def string: String = it

  trait HasRoles {
    def hasRole(code: RoleCode): Boolean
  }

  case class CompactGroup(
    code  : GroupCode,
    roles : Seq[RoleCode] = Seq.empty
  )

  object CompactGroup {
    def of(raw: RawGroup) = raw.transformInto[CompactGroup]
  }

  case class CompactApplication(
    id     : ApplicationId,
    code   : ApplicationCode,
    groups : Seq[CompactGroup] = Seq.empty
  )

  object CompactApplication {
    def of(raw: RawApplication) = raw.transformInto[CompactApplication]
  }

  case class CompactUser(
    details      : RawUserDetails,
    applications : Seq[CompactApplication] = Seq.empty
  )

  case class Token(
    created        : ZonedDateTime,
    expires        : Option[ZonedDateTime],
    user           : CompactUser,
    impersonatedBy : Option[RawUserDetails] = None
  ) {
    private def roleByCode(code: RoleCode)(using app: ApplicationCode): Option[RoleCode] =
      for {
        a <- user.applications.find(_.code == app)
        r <- a.groups.flatMap(_.roles).find(_ == code)
      } yield r

    def hasRole(code: RoleCode)(using ApplicationCode) =
      roleByCode(code).isDefined

    def narrowTo(application: ApplicationCode): Option[SingleAppToken] =
      user
        .applications
        .find(_.code == application)
        .map { found =>
          SingleAppToken(
            created,
            expires,
            SingleAppUser(details = user.details, application = found, impersonatedBy = impersonatedBy)
          )
        }
  }
  case class SingleAppUser(
    details        : RawUserDetails,
    application    : CompactApplication,
    impersonatedBy : Option[RawUserDetails] = None
  )

  case class SingleAppToken(
    created : ZonedDateTime,
    expires : Option[ZonedDateTime],
    user    : SingleAppUser
  ) {
    def hasRole(code: RoleCode): Boolean = user.application.groups.flatMap(_.roles).contains(code)
  }

  given Transformer[RawGroup, CompactGroup]             = (original: RawGroup)       => CompactGroup(code = original.code, roles = original.roles.map(_.code))
  given Transformer[RawApplication, CompactApplication] = (original: RawApplication) => CompactApplication(id = original.details.id, code = original.details.code, groups = original.groups.map(_.transformInto[CompactGroup]))

  given JsonCodec[CompactGroup]       = DeriveJsonCodec.gen
  given JsonCodec[CompactApplication] = DeriveJsonCodec.gen
  given JsonCodec[CompactUser]        = DeriveJsonCodec.gen
  given JsonCodec[Token]              = DeriveJsonCodec.gen
  given JsonCodec[SingleAppUser]      = DeriveJsonCodec.gen
  given JsonCodec[SingleAppToken]     = DeriveJsonCodec.gen
}

object requests {
  case class StoreGroupRequest(id: Option[GroupId], code: Option[GroupCode], name: GroupName, users: Seq[UserCode], roles: Seq[RoleCode])
  case class StoreUserRequest(id: Option[UserId], code: Option[UserCode], kind: Option[UserKind], email: Email, password: Option[Password], tenant: Option[TenantCode], active: Boolean, update: Boolean /* TODO: remove this as soon as we migrate all users from legacy */)
  case class StoreAccountRequest(id: Option[AccountId], tenant: TenantId, name: AccountName, code: AccountCode, active: Boolean, update: Boolean)
  case class RequestPasswordRequestLink(email: Email) extends HasEmail
  case class ChangePasswordRequest(email: Email, password: Password) extends HasEmail
  case class PasswordResetLink(link: Link)
  case class SetUserPin(email: Email, pin: Pin) extends HasEmail
  case class ValidateUserPin(pin: Pin)
  case class RemoveUserRequest(code: UserCode)
  case class RemoveGroupRequest(code: GroupCode)
  case class LoginViaEmailLinkRequest(email: Email, url: String)
  case class LoginViaEmailLinkResponse(link: Link)
  case class CreateAccount(tenant: TenantId, id: AccountId, code: AccountCode, name: AccountName, user: UserId, email: Email)
  case class ImpersonationRequest(email: Email, magic: Magic)

  given JsonCodec[StoreGroupRequest]          = DeriveJsonCodec.gen
  given JsonCodec[StoreUserRequest]           = DeriveJsonCodec.gen
  given JsonCodec[RequestPasswordRequestLink] = DeriveJsonCodec.gen
  given JsonCodec[PasswordResetLink]          = DeriveJsonCodec.gen
  given JsonCodec[SetUserPin]                 = DeriveJsonCodec.gen
  given JsonCodec[ValidateUserPin]            = DeriveJsonCodec.gen
  given JsonCodec[RemoveUserRequest]          = DeriveJsonCodec.gen
  given JsonCodec[RemoveGroupRequest]         = DeriveJsonCodec.gen
  given JsonCodec[LoginViaEmailLinkRequest]   = DeriveJsonCodec.gen
  given JsonCodec[LoginViaEmailLinkResponse]  = DeriveJsonCodec.gen
  given JsonCodec[StoreAccountRequest]        = DeriveJsonCodec.gen
  given JsonCodec[CreateAccount]              = DeriveJsonCodec.gen
  given JsonCodec[ChangePasswordRequest]      = DeriveJsonCodec.gen
  given JsonCodec[ImpersonationRequest]       = DeriveJsonCodec.gen
}