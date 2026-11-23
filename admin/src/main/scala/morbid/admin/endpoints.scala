package morbid.admin

import com.raquo.airstream.web.FetchOptions
import medulla.fetch.FetchRequest
import morbid.admin.api.*
import morbid.admin.api.codecs.given
import morbid.admin.codec.given
import morbid.types.*
import org.scalajs.dom

/** All protected admin-api endpoints carry the chosen application via the
  * `X-Admin-App` header. We build each FetchRequest with an extra `Opt` that
  * reads [[Session.selectedApp]] on every send so changing the app in the
  * TopBar takes effect immediately, without rebuilding the endpoints map. */
object Endpoints {

  private type Opt = FetchOptions[dom.BodyInit] => Unit

  private val defaultOpts: Seq[Opt] = Seq(_.credentials(_.include))

  /** Inject the `X-Admin-App` header on every protected call. Evaluated per
    * request: swapping the app in the TopBar is reflected on the next fetch. */
  private val adminAppOpt: Opt = fo =>
    Session.selectedApp.now().foreach { code =>
      fo.headersAppend("X-Admin-App" -> ApplicationCode.value(code))
    }

  /** FetchRequest for a protected admin-api endpoint — carries session cookie
    * and the chosen application header. */
  private def protectedRequest(path: String) =
    FetchRequest(path, defaultOpts ++ Seq(adminAppOpt))

  /** FetchRequest for a system-wide admin-api endpoint (applications, tenants):
    * carries the session cookie but NOT the `X-Admin-App` header, because
    * there's no app context here. Admin RBAC on writes falls back to
    * "admin on any app" server-side. */
  private def systemRequest(path: String) =
    FetchRequest(path, defaultOpts)

  /* auth — no `X-Admin-App` needed on these */

  def login       (body: LoginRequest)       = FetchRequest("/api/login")         .post[LoginRequest, LoginResponse](body)
  def getProvider (body: GetProviderRequest) = FetchRequest("/api/login/provider").post[GetProviderRequest, GetProviderResponse](body)
  def whoami                                 = FetchRequest("/api/me")            .get[LoginResponse]
  def logoff                                 = FetchRequest("/api/logoff")        .post[String, Boolean]("")

  /* accounts */

  def listAccounts                                            = protectedRequest("/api/accounts")                          .get[Seq[AccountResponse]]
  def createAccount (body: CreateAccountBody)                 = protectedRequest("/api/accounts")                          .post[CreateAccountBody, AccountResponse](body)
  def updateAccount (acc: AccountId, body: UpdateAccountBody) = protectedRequest(s"/api/accounts/${AccountId.value(acc)}") .put [UpdateAccountBody, AccountResponse](body)
  def deleteAccount (acc: AccountId)                          = protectedRequest(s"/api/accounts/${AccountId.value(acc)}") .delete[String, Boolean]("")

  /* users */

  def listUsers    (acc: AccountId)                                = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/users")                           .get[Seq[UserResponse]]
  def createUser   (acc: AccountId, body: CreateUserBody)          = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/users")                           .post[CreateUserBody, UserResponse](body)
  def updateUser   (acc: AccountId, code: UserCode, body: UpdateUserBody) =
    protectedRequest(s"/api/accounts/${AccountId.value(acc)}/users/${UserCode.value(code)}").put[UpdateUserBody, UserResponse](body)
  def deleteUser   (acc: AccountId, code: UserCode)                = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/users/${UserCode.value(code)}")   .delete[String, Boolean]("")
  def changePassword(body: ChangePasswordBody)                     = protectedRequest("/api/users/password/change")                                            .post[ChangePasswordBody, Boolean](body)
  def resetPassword (body: PasswordResetBody)                      = protectedRequest("/api/users/password/reset")                                             .post[PasswordResetBody, PasswordResetResponse](body)
  def setPin        (body: SetPinBody)                             = protectedRequest("/api/users/pin")                                                        .post[SetPinBody, Boolean](body)

  /* groups */

  def listGroups   (app: ApplicationCode, acc: Option[AccountId] = None) = {
    val suffix = acc.map(a => s"?acc=${AccountId.value(a)}").getOrElse("")
    protectedRequest(s"/api/apps/${ApplicationCode.value(app)}/groups$suffix").get[Seq[GroupResponse]]
  }
  def createGroup  (app: ApplicationCode, body: CreateGroupBody)         = protectedRequest(s"/api/apps/${ApplicationCode.value(app)}/groups")                                           .post[CreateGroupBody, GroupResponse](body)
  def deleteGroup  (app: ApplicationCode, code: GroupCode)               = protectedRequest(s"/api/apps/${ApplicationCode.value(app)}/groups/${GroupCode.value(code)}")                 .delete[String, Boolean]("")

  def listGroupUsers(acc: AccountId, app: ApplicationCode, grp: GroupCode) =
    protectedRequest(s"/api/accounts/${AccountId.value(acc)}/apps/${ApplicationCode.value(app)}/groups/${GroupCode.value(grp)}/users").get[Seq[UserResponse]]


  /* applications — system-wide, no X-Admin-App needed */

  def listApplications                             = systemRequest("/api/applications").get[Seq[ApplicationResponse]]
  def createApplication(body: CreateApplicationBody) = systemRequest("/api/applications").post[CreateApplicationBody, ApplicationResponse](body)
  def updateApplication(body: UpdateApplicationBody) = systemRequest("/api/applications").put [UpdateApplicationBody, ApplicationResponse](body)
  def deleteApplication(code: ApplicationCode)       = systemRequest(s"/api/applications/${ApplicationCode.value(code)}").delete[String, Boolean]("")

  /* roles — system-wide read, keyed by path app code */

  def listRoles(app: ApplicationCode) = systemRequest(s"/api/apps/${ApplicationCode.value(app)}/roles").get[Seq[RoleResponse]]

  /* tenants — system-wide, no X-Admin-App needed */

  def listTenants                              = systemRequest("/api/tenants")                           .get[Seq[TenantResponse]]
  def createTenant(body: CreateTenantBody)     = systemRequest("/api/tenants")                           .post[CreateTenantBody, TenantResponse](body)
  def updateTenant(id: TenantId, body: UpdateTenantBody) =
    systemRequest(s"/api/tenants/${TenantId.value(id)}").put[UpdateTenantBody, TenantResponse](body)
  def deleteTenant(id: TenantId)               = systemRequest(s"/api/tenants/${TenantId.value(id)}")     .delete[String, Boolean]("")

  /* identity providers */

  def listProviders  (acc: AccountId)                           = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/providers")                            .get[Seq[ProviderResponse]]
  def createProvider (acc: AccountId, body: CreateProviderBody) = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/providers")                            .post[CreateProviderBody, ProviderResponse](body)
  def updateProvider (acc: AccountId, id: ProviderId, body: UpdateProviderBody) =
    protectedRequest(s"/api/accounts/${AccountId.value(acc)}/providers/${ProviderId.value(id)}").put[UpdateProviderBody, ProviderResponse](body)
  def deleteProvider (acc: AccountId, id: ProviderId)           = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/providers/${ProviderId.value(id)}")    .delete[String, Boolean]("")

  /* api keys (service accounts) */

  def listApiKeys (acc: AccountId)                             = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/api-keys")                              .get[Seq[ApiKeyResponse]]
  def issueApiKey (acc: AccountId, body: CreateApiKeyBody)     = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/api-keys")                              .post[CreateApiKeyBody, ApiKeyIssuedResponse](body)
  def deleteApiKey(acc: AccountId, code: UserCode)             = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/api-keys/${UserCode.value(code)}")      .delete[String, Boolean]("")

  /* per-account app enable/disable */

  def listAccountApps  (acc: AccountId)                               = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/apps")                                                .get[Seq[ApplicationResponse]]
  def linkAccountApp   (acc: AccountId, code: ApplicationCode)        = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/apps/${ApplicationCode.value(code)}")                 .post[String, Boolean]("")
  def unlinkAccountApp (acc: AccountId, code: ApplicationCode)        = protectedRequest(s"/api/accounts/${AccountId.value(acc)}/apps/${ApplicationCode.value(code)}")                 .delete[String, Boolean]("")
}
