package morbid.client.okhttp

import okhttp3.{MediaType, OkHttpClient, Request, RequestBody, Response}
import org.slf4j.LoggerFactory

import java.net.URLEncoder
import scala.concurrent.{ExecutionContext, Future}

/**
 * OkHttp3-based implementation of MorbidClient that calls the morbid (m) server.
 *
 * @param baseUrl the base URL of the morbid server (e.g. "https://morbid.example.com/v1")
 * @param ec      implicit ExecutionContext for async operations
 */
class RemoteMorbidClient(baseUrl: String, httpClient: OkHttpClient = new OkHttpClient())(implicit ec: ExecutionContext) extends MorbidClient {

  private val logger    = LoggerFactory.getLogger(getClass)
  private val JSON_TYPE = MediaType.parse("application/json; charset=utf-8")

  private def url(parts: String*): String =
    baseUrl.stripSuffix("/") + parts.map(p => "/" + URLEncoder.encode(p, "UTF-8")).mkString

  // --- HTTP helpers ---

  private def getRequest(url: String, token: Option[String] = None, serviceToken: Option[String] = None): Request = {
    val builder = new Request.Builder().url(url).get()
    token.foreach(t        => builder.addHeader("X-MorbidToken", t))
    serviceToken.foreach(t => builder.addHeader("X-Morbid-Service-Token", t))
    builder.build()
  }

  private def postRequest(url: String, body: String, token: Option[String] = None): Request = {
    val builder = new Request.Builder()
      .url(url)
      .post(RequestBody.create(body, JSON_TYPE))
    token.foreach(t => builder.addHeader("X-MorbidToken", t))
    builder.build()
  }

  private def deleteRequest(url: String, token: Option[String] = None): Request = {
    val builder = new Request.Builder().url(url).delete()
    token.foreach(t => builder.addHeader("X-MorbidToken", t))
    builder.build()
  }

  private def exec[T](request: Request)(implicit m: Manifest[T]): Future[Either[Throwable, T]] = Future {
    var response: Response = null
    try {
      logger.debug("Calling '{}'", request.url())
      response = httpClient.newCall(request).execute()
      if (response.isSuccessful) {
        val body = response.body().string()
        Right(Json.decode[T](body))
      } else {
        val body = Option(response.body()).map(_.string()).getOrElse("")
        Left(new RuntimeException(s"HTTP ${response.code()}: $body"))
      }
    } catch {
      case e: Exception => Left(e)
    } finally {
      if (response != null) response.close()
    }
  }

  private def execSeq[T](request: Request)(implicit m: Manifest[T]): Future[Either[Throwable, Seq[T]]] = Future {
    var response: Response = null
    try {
      logger.debug("Calling '{}'", request.url())
      response = httpClient.newCall(request).execute()
      if (response.isSuccessful) {
        val body = response.body().string()
        Right(Json.decodeSeq[T](body))
      } else {
        val body = Option(response.body()).map(_.string()).getOrElse("")
        Left(new RuntimeException(s"HTTP ${response.code()}: $body"))
      }
    } catch {
      case e: Exception => Left(e)
    } finally {
      if (response != null) response.close()
    }
  }

  private def execOption[T](request: Request)(implicit m: Manifest[T]): Future[Either[Throwable, Option[T]]] = Future {
    var response: Response = null
    try {
      logger.debug("Calling '{}'", request.url())
      response = httpClient.newCall(request).execute()
      response.code() match {
        case 200 =>
          val body = response.body().string()
          Right(Some(Json.decode[T](body)))
        case 404 =>
          Right(None)
        case code =>
          val body = Option(response.body()).map(_.string()).getOrElse("")
          Left(new RuntimeException(s"HTTP $code: $body"))
      }
    } catch {
      case e: Exception => Left(e)
    } finally {
      if (response != null) response.close()
    }
  }

  // --- Token ---

  override def verify(token: String): Future[Either[Throwable, Token]] =
    exec[Token](postRequest(url("verify"), Json.encode(SimpleToken(token)), Some(token)))

  // --- Users ---

  override def users(token: String, app: String): Future[Either[Throwable, Seq[RawUserEntry]]] =
    execSeq[RawUserEntry](getRequest(url("app", app, "users"), Some(token)))

  override def storeUser(token: String, app: String, request: StoreUserRequest): Future[Either[Throwable, RawUserEntry]] =
    exec[RawUserEntry](postRequest(url("app", app, "user"), Json.encode(request), Some(token)))

  override def removeUser(token: String, app: String, request: RemoveUserRequest): Future[Either[Throwable, Long]] =
    exec[Long](postRequest(url("app", app, "user", "delete"), Json.encode(request), Some(token)))

  override def userByEmail(email: String): Future[Either[Throwable, Option[RawUserEntry]]] = {
    val u = baseUrl.stripSuffix("/") + "/user?email=" + URLEncoder.encode(email, "UTF-8")
    execOption[RawUserEntry](getRequest(u))
  }

  override def userById(id: Long): Future[Either[Throwable, Option[RawUserEntry]]] = {
    val u = baseUrl.stripSuffix("/") + "/user?id=" + id
    execOption[RawUserEntry](getRequest(u))
  }

  // --- Groups ---

  override def groups(token: String, app: String): Future[Either[Throwable, Seq[RawGroup]]] =
    execSeq[RawGroup](getRequest(url("app", app, "groups"), Some(token)))

  override def storeGroup(token: String, app: String, request: StoreGroupRequest): Future[Either[Throwable, RawGroup]] =
    exec[RawGroup](postRequest(url("app", app, "group"), Json.encode(request), Some(token)))

  override def removeGroup(token: String, app: String, request: RemoveGroupRequest): Future[Either[Throwable, Long]] =
    exec[Long](postRequest(url("app", app, "group", "delete"), Json.encode(request), Some(token)))

  override def usersByGroup(token: String, app: String, group: String): Future[Either[Throwable, Seq[RawUserEntry]]] =
    execSeq[RawUserEntry](getRequest(url("app", app, "group", group, "users"), Some(token)))

  // --- Roles ---

  override def roles(token: String, app: String): Future[Either[Throwable, Seq[RawRole]]] =
    execSeq[RawRole](getRequest(url("app", app, "roles"), Some(token)))

  // --- Password ---

  override def passwordResetLink(token: String, app: String, request: RequestPasswordResetLink): Future[Either[Throwable, PasswordResetLink]] =
    exec[PasswordResetLink](postRequest(url("app", app, "password", "reset"), Json.encode(request), Some(token)))

  override def passwordChange(token: String, app: String, request: ChangePasswordRequest): Future[Either[Throwable, Boolean]] =
    exec[Boolean](postRequest(url("app", app, "password", "change"), Json.encode(request), Some(token)))

  // --- PIN ---

  override def setPin(token: String, app: String, request: SetUserPin): Future[Either[Throwable, Boolean]] =
    exec[Boolean](postRequest(url("app", app, "user", "pin"), Json.encode(request), Some(token)))

  override def validatePin(token: String, request: ValidateUserPin): Future[Either[Throwable, Boolean]] =
    exec[Boolean](postRequest(url("user", "pin", "validate"), Json.encode(request), Some(token)))

  // --- Impersonation ---

  override def impersonate(token: String, request: ImpersonationRequest): Future[Either[Throwable, Token]] =
    exec[Token](postRequest(url("impersonate"), Json.encode(request), Some(token)))

  // --- Manager ---

  override def managerGetAccounts(token: String, app: String): Future[Either[Throwable, Seq[RawAccount]]] =
    execSeq[RawAccount](getRequest(url("app", app, "manager", "accounts"), Some(token)))

  override def managerStoreAccount(token: String, app: String, request: StoreAccountRequest): Future[Either[Throwable, RawAccount]] =
    exec[RawAccount](postRequest(url("app", app, "manager", "account"), Json.encode(request), Some(token)))

  override def managerRemoveAccount(token: String, app: String, account: Long): Future[Either[Throwable, Boolean]] =
    exec[Boolean](deleteRequest(url("app", app, "manager", "account", account.toString), Some(token)))

  override def managerGetUsers(token: String, app: String, account: Long): Future[Either[Throwable, Seq[RawUserEntry]]] =
    execSeq[RawUserEntry](getRequest(url("app", app, "manager", "account", account.toString, "users"), Some(token)))

  override def managerStoreUser(token: String, app: String, account: Long, request: StoreUserRequest): Future[Either[Throwable, RawUserEntry]] =
    exec[RawUserEntry](postRequest(url("app", app, "manager", "account", account.toString, "user"), Json.encode(request), Some(token)))

  override def managerRemoveUser(token: String, app: String, account: Long, code: String): Future[Either[Throwable, Boolean]] =
    exec[Boolean](deleteRequest(url("app", app, "manager", "account", account.toString, "user", code), Some(token)))

  // --- Service endpoints ---

  override def serviceUsers(serviceToken: String, app: String): Future[Either[Throwable, Seq[RawUserEntry]]] =
    execSeq[RawUserEntry](getRequest(url("service", "app", app, "users"), serviceToken = Some(serviceToken)))

  override def serviceAccounts(serviceToken: String, app: String): Future[Either[Throwable, Seq[RawAccount]]] =
    execSeq[RawAccount](getRequest(url("service", "app", app, "accounts"), serviceToken = Some(serviceToken)))
}
