package morbid.client.okhttp

import io.jsonwebtoken.{Jws, Jwts}
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Paths}
import java.time.{ZoneId, ZonedDateTime}
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.{ExecutionContext, Future}

/**
 * Morbid client that verifies tokens locally using the JWT secret key,
 * and delegates all other operations to a RemoteMorbidClient.
 *
 * @param keyPath  path to the Base64-encoded HS512 secret key file
 * @param timezone timezone for token expiration checks (default: America/Sao_Paulo)
 * @param remote   the remote client for non-token operations
 * @param ec       implicit ExecutionContext
 */
class LocalMorbidClient(
  keyPath  : String,
  timezone : String = "America/Sao_Paulo",
  remote   : RemoteMorbidClient
)(implicit ec: ExecutionContext) extends MorbidClient {

  private val logger = LoggerFactory.getLogger(getClass)
  private val zone   = ZoneId.of(timezone)
  private val parser = {
    val bytes   = Files.readAllBytes(Paths.get(keyPath))
    val decoded = Base64.getDecoder.decode(bytes)
    val key     = new SecretKeySpec(decoded, 0, decoded.length, "HmacSHA512")
    logger.info("Loaded JWT key from '{}' for local token verification", keyPath)
    Jwts.parser().verifyWith(key).build()
  }

  override def verify(token: String): Future[Either[Throwable, Token]] = Future {
    try {
      logger.debug("Verifying token locally")
      val generic = parser.parse(token)
      val payload = generic.accept(Jws.CONTENT).getPayload
      val parsed  = Json.decode[Token](new String(payload))
      val now     = ZonedDateTime.now(zone)
      parsed.expires match {
        case Some(exp) if now.isAfter(exp) =>
          Left(new RuntimeException(s"Token is expired since '$exp'"))
        case _ =>
          Right(parsed)
      }
    } catch {
      case e: Exception => Left(e)
    }
  }

  // --- Delegate everything else to remote ---

  override def users(token: String, app: String)                                                      = remote.users(token, app)
  override def storeUser(token: String, app: String, request: StoreUserRequest)                       = remote.storeUser(token, app, request)
  override def removeUser(token: String, app: String, request: RemoveUserRequest)                     = remote.removeUser(token, app, request)
  override def userByEmail(email: String)                                                             = remote.userByEmail(email)
  override def userById(id: Long)                                                                     = remote.userById(id)
  override def groups(token: String, app: String)                                                     = remote.groups(token, app)
  override def storeGroup(token: String, app: String, request: StoreGroupRequest)                     = remote.storeGroup(token, app, request)
  override def removeGroup(token: String, app: String, request: RemoveGroupRequest)                   = remote.removeGroup(token, app, request)
  override def usersByGroup(token: String, app: String, group: String)                                = remote.usersByGroup(token, app, group)
  override def roles(token: String, app: String)                                                      = remote.roles(token, app)
  override def passwordResetLink(token: String, app: String, request: RequestPasswordResetLink)       = remote.passwordResetLink(token, app, request)
  override def passwordChange(token: String, app: String, request: ChangePasswordRequest)             = remote.passwordChange(token, app, request)
  override def setPin(token: String, app: String, request: SetUserPin)                                = remote.setPin(token, app, request)
  override def validatePin(token: String, request: ValidateUserPin)                                   = remote.validatePin(token, request)
  override def impersonate(token: String, request: ImpersonationRequest)                              = remote.impersonate(token, request)
  override def managerGetAccounts(token: String, app: String)                                         = remote.managerGetAccounts(token, app)
  override def managerStoreAccount(token: String, app: String, request: StoreAccountRequest)          = remote.managerStoreAccount(token, app, request)
  override def managerRemoveAccount(token: String, app: String, account: Long)                        = remote.managerRemoveAccount(token, app, account)
  override def managerGetUsers(token: String, app: String, account: Long)                             = remote.managerGetUsers(token, app, account)
  override def managerStoreUser(token: String, app: String, account: Long, request: StoreUserRequest) = remote.managerStoreUser(token, app, account, request)
  override def managerRemoveUser(token: String, app: String, account: Long, code: String)             = remote.managerRemoveUser(token, app, account, code)
  override def serviceUsers(serviceToken: String, app: String)                                        = remote.serviceUsers(serviceToken, app)
  override def serviceAccounts(serviceToken: String, app: String)                                     = remote.serviceAccounts(serviceToken, app)
}
