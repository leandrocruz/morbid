package morbid.client.okhttp

import scala.concurrent.{ExecutionContext, Future}

/**
 * Morbid client interface for JVM services (Scala 2.12 compatible).
 * Talks to the morbid (m) server using OkHttp3.
 *
 * All app-scoped operations require an `app` parameter (ApplicationCode).
 */
trait MorbidClient {

  // --- Token ---
  def verify(token: String)                                                       : Future[Either[Throwable, Token]]

  // --- Users ---
  def users          (token: String, app: String)                                 : Future[Either[Throwable, Seq[RawUserEntry]]]
  def storeUser      (token: String, app: String, request: StoreUserRequest)      : Future[Either[Throwable, RawUserEntry]]
  def removeUser     (token: String, app: String, request: RemoveUserRequest)     : Future[Either[Throwable, Long]]
  def userByEmail    (email: String)                                              : Future[Either[Throwable, Option[RawUserEntry]]]
  def userById       (id: Long)                                                   : Future[Either[Throwable, Option[RawUserEntry]]]

  // --- Groups ---
  def groups         (token: String, app: String)                                 : Future[Either[Throwable, Seq[RawGroup]]]
  def storeGroup     (token: String, app: String, request: StoreGroupRequest)     : Future[Either[Throwable, RawGroup]]
  def removeGroup    (token: String, app: String, request: RemoveGroupRequest)    : Future[Either[Throwable, Long]]
  def usersByGroup   (token: String, app: String, group: String)                  : Future[Either[Throwable, Seq[RawUserEntry]]]

  // --- Roles ---
  def roles          (token: String, app: String)                                 : Future[Either[Throwable, Seq[RawRole]]]

  // --- Password ---
  def passwordResetLink(token: String, app: String, request: RequestPasswordResetLink) : Future[Either[Throwable, PasswordResetLink]]
  def passwordChange   (token: String, app: String, request: ChangePasswordRequest)    : Future[Either[Throwable, Boolean]]

  // --- PIN ---
  def setPin         (token: String, app: String, request: SetUserPin)            : Future[Either[Throwable, Boolean]]
  def validatePin    (token: String, request: ValidateUserPin)                    : Future[Either[Throwable, Boolean]]

  // --- Impersonation ---
  def impersonate    (token: String, request: ImpersonationRequest)               : Future[Either[Throwable, Token]]

  // --- Manager (root account only) ---
  def managerGetAccounts  (token: String, app: String)                                              : Future[Either[Throwable, Seq[RawAccount]]]
  def managerStoreAccount (token: String, app: String, request: StoreAccountRequest)                : Future[Either[Throwable, RawAccount]]
  def managerRemoveAccount(token: String, app: String, account: Long)                               : Future[Either[Throwable, Boolean]]
  def managerGetUsers     (token: String, app: String, account: Long)                               : Future[Either[Throwable, Seq[RawUserEntry]]]
  def managerStoreUser    (token: String, app: String, account: Long, request: StoreUserRequest)    : Future[Either[Throwable, RawUserEntry]]
  def managerRemoveUser   (token: String, app: String, account: Long, code: String)                 : Future[Either[Throwable, Boolean]]

  // --- Service endpoints (requires service token) ---
  def serviceUsers    (serviceToken: String, app: String)                         : Future[Either[Throwable, Seq[RawUserEntry]]]
  def serviceAccounts (serviceToken: String, app: String)                         : Future[Either[Throwable, Seq[RawAccount]]]
}
