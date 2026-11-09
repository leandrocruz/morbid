package morbid

object domain {

  import types.*
  import domain.token.{SingleAppUser, CompactApplication}
  import zio.json.*
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

    case class RawTenant(
      id   : TenantId,
      code : TenantCode,
    )

    case class RawTenantDetails(
      id      : TenantId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      active  : Boolean,
      code    : TenantCode,
      name    : TenantName,
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
      identifier : Option[AccountIdentifier] = None,
    )

    case class RawAccountAdmin(
      id    : AccountId,
      name  : AccountName,
      users : Seq[RawUserEntry]
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

    case class AccountWithApps(
      account : RawAccount,
      apps    : Seq[RawApplicationDetails]
    )

    case class RawApplication(
      details : RawApplicationDetails,
      groups  : Seq[RawGroup] = Seq.empty,
      plans   : Seq[RawPlan]  = Seq.empty
    )

    case class RawFeature(
      id          : FeatureId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime],
      app         : ApplicationId,
      code        : FeatureCode,
      name        : FeatureName,
      description : Option[String] = None,
    )

    case class RawPlanFeature(
      feature : RawFeature,
      value   : Option[Long] = None,
    )

    case class RawPlan(
      id          : PlanId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime],
      active      : Boolean,
      app         : ApplicationId,
      code        : PlanCode,
      name        : PlanName,
      description : Option[String]         = None,
      features    : Seq[RawPlanFeature]    = Seq.empty,
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

    given JsonCodec[RawApplicationDetails] = DeriveJsonCodec.gen
    given JsonCodec[RawFeature]            = DeriveJsonCodec.gen
    given JsonCodec[RawPlanFeature]        = DeriveJsonCodec.gen
    given JsonCodec[RawPlan]               = DeriveJsonCodec.gen
    given JsonCodec[RawApplication]        = DeriveJsonCodec.gen
    given JsonCodec[RawUserData]           = DeriveJsonCodec.gen
    given JsonCodec[RawUserDetails]        = DeriveJsonCodec.gen
    given JsonCodec[RawGroup]              = DeriveJsonCodec.gen
    given JsonCodec[RawPermission]         = DeriveJsonCodec.gen
    given JsonCodec[RawRole]               = DeriveJsonCodec.gen
    given JsonCodec[RawUser]               = DeriveJsonCodec.gen
    given JsonCodec[RawUserEntry]          = DeriveJsonCodec.gen
    given JsonCodec[RawAccountAdmin]       = DeriveJsonCodec.gen
    given JsonCodec[RawAccount]            = DeriveJsonCodec.gen
    given JsonCodec[RawIdentityProvider]   = DeriveJsonCodec.gen
    given JsonCodec[RawTenantDetails]      = DeriveJsonCodec.gen
    given JsonCodec[AccountWithApps]       = DeriveJsonCodec.gen
  }

  object token {

    import morbid.domain.raw.*
    import java.time.ZonedDateTime

    opaque type ServiceToken = String
    opaque type RawToken     = String

    object ServiceToken {
      def of(value: String): ServiceToken = value
      given JsonCodec[ServiceToken]       = JsonCodec.string
    }

    object RawToken {
      def of(value: String): RawToken = value
      given JsonCodec[RawToken] = JsonCodec.string
    }

    extension (it: RawToken | ServiceToken)
      def string: String = it

    trait HasRoles {
      def hasRole(code: RoleCode): Boolean
    }

    case class CompactGroup(
      code  : GroupCode,
      roles : Seq[RoleCode] = Seq.empty
    )

    object CompactGroup {
      def of(raw: RawGroup): CompactGroup = CompactGroup(code = raw.code, roles = raw.roles.map(_.code))
    }

    case class CompactFeature(
      code  : FeatureCode,
      value : Option[Long] = None,
    )

    case class CompactPlan(
      code     : PlanCode,
      features : Seq[CompactFeature] = Seq.empty
    )

    object CompactPlan {
      def of(raw: RawPlan): CompactPlan =
        CompactPlan(
          code     = raw.code,
          features = raw.features.map(f => CompactFeature(code = f.feature.code, value = f.value))
        )
    }

    case class CompactApplication(
      id     : ApplicationId,
      code   : ApplicationCode,
      groups : Seq[CompactGroup] = Seq.empty,
      plans  : Seq[CompactPlan]  = Seq.empty
    )

    object CompactApplication {
      def of(raw: RawApplication): CompactApplication = CompactApplication(
        id     = raw.details.id,
        code   = raw.details.code,
        groups = raw.groups.map(CompactGroup.of),
        plans  = raw.plans.map(CompactPlan.of)
      )
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
        for
          a <- user.applications.find(_.code == app)
          r <- a.groups.flatMap(_.roles).find(_ == code)
        yield r

      def hasRole(code: RoleCode)(using ApplicationCode) = roleByCode(code).isDefined

      def features(using app: ApplicationCode): Seq[CompactFeature] =
        user
          .applications
          .find(_.code == app)
          .toSeq
          .flatMap(_.plans.flatMap(_.features))

      def featureCodes(using ApplicationCode): Set[FeatureCode] = features.map(_.code).toSet
      def hasFeature(code: FeatureCode)(using ApplicationCode): Boolean = features.exists(_.code == code)

      def featureValue(code: FeatureCode)(using ApplicationCode): Option[Long] = {
        val values = features.filter(_.code == code).flatMap(_.value)
        if values.isEmpty then None else Some(values.sum)
      }

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

      def isRoot = user.details.account == RootAccount
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
      def hasRole     (code: RoleCode)    : Boolean             = user.application.groups.flatMap(_.roles).contains(code)
      def features                        : Seq[CompactFeature] = user.application.plans.flatMap(_.features)
      def featureCodes                    : Set[FeatureCode]    = features.map(_.code).toSet
      def hasFeature  (code: FeatureCode) : Boolean             = features.exists(_.code == code)

      def featureValue(code: FeatureCode) : Option[Long] = {
        val values = features.filter(_.code == code).flatMap(_.value)
        if values.isEmpty then None else Some(values.sum)
      }
    }

    given JsonCodec[CompactGroup]       = DeriveJsonCodec.gen
    given JsonCodec[CompactFeature]     = DeriveJsonCodec.gen
    given JsonCodec[CompactPlan]        = DeriveJsonCodec.gen
    given JsonCodec[CompactApplication] = DeriveJsonCodec.gen
    given JsonCodec[CompactUser]        = DeriveJsonCodec.gen
    given JsonCodec[Token]              = DeriveJsonCodec.gen
    given JsonCodec[SingleAppUser]      = DeriveJsonCodec.gen
    given JsonCodec[SingleAppToken]     = DeriveJsonCodec.gen
  }

  object requests {

    import morbid.domain.raw.RawUserEntry

    case class StoreGroupRequest(id: Option[GroupId], code: Option[GroupCode], name: GroupName, users: Seq[UserCode], roles: Seq[RoleCode])
    case class StoreUserRequest(id: Option[UserId], code: Option[UserCode], kind: Option[UserKind], email: Email, password: Option[Password], tenant: Option[TenantCode], active: Boolean, update: Boolean /* TODO: remove this as soon as we migrate all users from legacy */)
    case class StoreAccountRequest(id: Option[AccountId], tenant: TenantId, name: AccountName, code: AccountCode, active: Boolean, update: Boolean, identifier: Option[AccountIdentifier] = None)
    case class RequestPasswordRequestLink(email: Email) extends HasEmail
    case class ChangePasswordRequest(email: Email, password: Password) extends HasEmail
    case class PasswordResetLink(link: Link)
    case class SetUserPin(email: Email, pin: Pin) extends HasEmail
    case class ValidateUserPin(pin: Pin)
    case class RemoveUserRequest(code: UserCode)
    case class RemoveGroupRequest(code: GroupCode)
    case class GetUserGroupsRequest(user: UserCode)
    case class SetUserGroupsRequest(user: UserCode, groups: Seq[GroupCode])
    case class LoginViaEmailLinkRequest(email: Email, url: String)
    case class LoginViaEmailLinkResponse(link: Link)
    case class CreateAccount(tenant: TenantId, id: AccountId, code: AccountCode, name: AccountName, user: UserId, email: Email, identifier: Option[AccountIdentifier] = None)
    case class FindAccountByIdentifierRequest(magic: Magic, identifier: AccountIdentifier)
    case class ImpersonationRequest(email: Email, magic: Magic)
    case class ImpersonateAccountAdminRequest(magic: Magic)
    case class LogoffResponse(restored: Boolean)
    case class GetAccountPlansRequest(account: AccountId, application: ApplicationCode)

    case class ProvisionRequest(
      magic       : Magic,
      tenant      : TenantCode,
      application : ApplicationCode,
      plan        : PlanCode,
      account     : AccountName,
      name        : String,
      email       : Email,
      password    : Password,
      groups      : Map[GroupCode, Seq[RoleCode]],
      accountType : String,
      userType    : String,
      identifier  : Option[AccountIdentifier] = None,
    )
    case class StoreTenantRequest(
      id     : Option[TenantId],
      code   : TenantCode,
      name   : TenantName,
      active : Boolean,
    )
    case class StoreIdentityProviderRequest(
      id      : Option[ProviderId],
      active  : Boolean,
      domain  : Domain,
      kind    : ProviderKind,
      code    : ProviderCode,
      name    : ProviderName,
    )

    case class CreateApiKeyRequest(
      email : Email,
      name  : Option[String] = None,
      days  : Option[Int]    = None,
    )

    case class ApiKeyIssued(
      user  : morbid.domain.raw.RawUserEntry,
      token : String,
    )

    given JsonCodec[StoreGroupRequest]              = DeriveJsonCodec.gen
    given JsonCodec[StoreUserRequest]               = DeriveJsonCodec.gen
    given JsonCodec[RequestPasswordRequestLink]     = DeriveJsonCodec.gen
    given JsonCodec[PasswordResetLink]              = DeriveJsonCodec.gen
    given JsonCodec[SetUserPin]                     = DeriveJsonCodec.gen
    given JsonCodec[ValidateUserPin]                = DeriveJsonCodec.gen
    given JsonCodec[RemoveUserRequest]              = DeriveJsonCodec.gen
    given JsonCodec[RemoveGroupRequest]             = DeriveJsonCodec.gen
    given JsonCodec[GetUserGroupsRequest]           = DeriveJsonCodec.gen
    given JsonCodec[SetUserGroupsRequest]           = DeriveJsonCodec.gen
    given JsonCodec[LoginViaEmailLinkRequest]       = DeriveJsonCodec.gen
    given JsonCodec[LoginViaEmailLinkResponse]      = DeriveJsonCodec.gen
    given JsonCodec[ProvisionRequest]               = DeriveJsonCodec.gen
    given JsonCodec[GetAccountPlansRequest]         = DeriveJsonCodec.gen
    given JsonCodec[StoreAccountRequest]            = DeriveJsonCodec.gen
    given JsonCodec[CreateAccount]                  = DeriveJsonCodec.gen
    given JsonCodec[FindAccountByIdentifierRequest] = DeriveJsonCodec.gen
    given JsonCodec[ChangePasswordRequest]          = DeriveJsonCodec.gen
    given JsonCodec[ImpersonationRequest]           = DeriveJsonCodec.gen
    given JsonCodec[ImpersonateAccountAdminRequest] = DeriveJsonCodec.gen
    given JsonCodec[LogoffResponse]                 = DeriveJsonCodec.gen
    given JsonCodec[StoreTenantRequest]             = DeriveJsonCodec.gen
    given JsonCodec[StoreIdentityProviderRequest]   = DeriveJsonCodec.gen
    given JsonCodec[CreateApiKeyRequest]            = DeriveJsonCodec.gen
    given JsonCodec[ApiKeyIssued]                   = DeriveJsonCodec.gen
  }
}
