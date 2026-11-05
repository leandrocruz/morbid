package morbid.admin

import medulla.fetch.FetchRequest
import morbid.admin.api.*
import morbid.admin.api.codecs.given
import morbid.admin.codec.given
import morbid.types.*

object Endpoints {

  /* auth */

  def login       (body: LoginRequest)       = FetchRequest("/api/login")         .post[LoginRequest, LoginResponse](body)
  def getProvider (body: GetProviderRequest) = FetchRequest("/api/login/provider").post[GetProviderRequest, GetProviderResponse](body)
  def whoami                                 = FetchRequest("/api/me")            .get[LoginResponse]
  def logoff                                 = FetchRequest("/api/logoff")        .post[String, Boolean]("")

  /* accounts */

  def listAccounts                                            = FetchRequest("/api/accounts")                          .get[Seq[AccountResponse]]
  def createAccount (body: CreateAccountBody)                 = FetchRequest("/api/accounts")                          .post[CreateAccountBody, AccountResponse](body)
  def updateAccount (acc: AccountId, body: UpdateAccountBody) = FetchRequest(s"/api/accounts/${AccountId.value(acc)}") .put [UpdateAccountBody, AccountResponse](body)
  def deleteAccount (acc: AccountId)                          = FetchRequest(s"/api/accounts/${AccountId.value(acc)}") .delete[String, Boolean]("")

  /* users */

  def listUsers    (acc: AccountId)                                = FetchRequest(s"/api/accounts/${AccountId.value(acc)}/users")                           .get[Seq[UserResponse]]
  def createUser   (acc: AccountId, body: CreateUserBody)          = FetchRequest(s"/api/accounts/${AccountId.value(acc)}/users")                           .post[CreateUserBody, UserResponse](body)
  def updateUser   (acc: AccountId, code: UserCode, body: UpdateUserBody) =
    FetchRequest(s"/api/accounts/${AccountId.value(acc)}/users/${UserCode.value(code)}").put[UpdateUserBody, UserResponse](body)
  def deleteUser   (acc: AccountId, code: UserCode)                = FetchRequest(s"/api/accounts/${AccountId.value(acc)}/users/${UserCode.value(code)}")   .delete[String, Boolean]("")
  def changePassword(body: ChangePasswordBody)                     = FetchRequest("/api/users/password/change")                                            .post[ChangePasswordBody, Boolean](body)
  def resetPassword (body: PasswordResetBody)                      = FetchRequest("/api/users/password/reset")                                             .post[PasswordResetBody, PasswordResetResponse](body)
  def setPin        (body: SetPinBody)                             = FetchRequest("/api/users/pin")                                                        .post[SetPinBody, Boolean](body)

  /* groups */

  def listGroups   (app: ApplicationCode)                                = FetchRequest(s"/api/apps/${ApplicationCode.value(app)}/groups")                                           .get[Seq[GroupResponse]]
  def createGroup  (app: ApplicationCode, body: CreateGroupBody)         = FetchRequest(s"/api/apps/${ApplicationCode.value(app)}/groups")                                           .post[CreateGroupBody, GroupResponse](body)
  def deleteGroup  (app: ApplicationCode, code: GroupCode)               = FetchRequest(s"/api/apps/${ApplicationCode.value(app)}/groups/${GroupCode.value(code)}")                 .delete[String, Boolean]("")

  /* applications */

  def listApplications                             = FetchRequest("/api/applications").get[Seq[ApplicationResponse]]
  def createApplication(body: CreateApplicationBody) = FetchRequest("/api/applications").post[CreateApplicationBody, ApplicationResponse](body)
  def updateApplication(body: UpdateApplicationBody) = FetchRequest("/api/applications").put [UpdateApplicationBody, ApplicationResponse](body)

  /* roles */

  def listRoles(app: ApplicationCode) = FetchRequest(s"/api/apps/${ApplicationCode.value(app)}/roles").get[Seq[RoleResponse]]
}
