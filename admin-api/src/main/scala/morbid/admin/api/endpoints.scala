package morbid.admin.api

import morbid.admin.api.codecs.given
import morbid.admin.api.dtoSchemas.given
import morbid.admin.api.schemas.given
import neotype.interop.zioschema.given
import zio.ZNothing
import zio.http.*
import zio.http.codec.*
import zio.http.endpoint.*

/** Endpoint declarations in the partner-api style: inputs/outputs are typed, errors
  * are declared once via [[uefErrors]] so every route serializes failures as the UEF
  * payload. The handlers in [[router]] implement each of these.
  *
  * Paths DO NOT include the `/api/` ingress prefix — nginx strips it before proxying.
  *
  * Every protected endpoint (except /me and /logoff) carries the `X-Admin-App`
  * header: the application the admin is currently working on. Reads use it to build
  * the correct manager URL on morbid; writes additionally use it for the RBAC check
  * (the user must carry the `adm` role on that application).
  */
object endpoints {

  private val accParam = string("acc")
  private val usrParam = string("usr")
  private val grpParam = string("grp")
  private val appParam = string("app")
  private val tnParam  = string("tn")
  private val prvParam = string("prv")
  private val keyParam = string("key")

  private val cookieHeader   = HeaderCodec.headerAs[String]("cookie").optional
  private val authHeader     = HeaderCodec.headerAs[AuthorizationHeader]("authorization").optional
  private val adminAppHeader = HeaderCodec.headerAs[String]("x-admin-app").optional

  private def uefErrors[PathInput, Input, Output, Auth <: AuthType](
    endpoint: Endpoint[PathInput, Input, ZNothing, Output, Auth]
  ) =
    endpoint.outErrors[ApiError](
      ContentCodec.content[ApiError.BadInput]     ++ StatusCodec.status(Status.BadRequest),
      ContentCodec.content[ApiError.Unauthorized] ++ StatusCodec.status(Status.Unauthorized),
      ContentCodec.content[ApiError.Forbidden]    ++ StatusCodec.status(Status.Forbidden),
      ContentCodec.content[ApiError.NotFound]     ++ StatusCodec.status(Status.NotFound),
      ContentCodec.content[ApiError.Conflict]     ++ StatusCodec.status(Status.Conflict),
      ContentCodec.content[ApiError.Upstream]     ++ StatusCodec.status(Status.BadGateway),
      ContentCodec.content[ApiError.Internal]     ++ StatusCodec.status(Status.InternalServerError),
    ).outCodecError(ApiError.uefCodecError)

  /* auth */

  val login = uefErrors(
    Endpoint(Method.POST / "login")
      .in[LoginRequest]
      .out[LoginResponse]
  )

  val loginProvider = uefErrors(
    Endpoint(Method.POST / "login" / "provider")
      .in[GetProviderRequest]
      .out[GetProviderResponse]
  )

  val logoff = uefErrors(
    Endpoint(Method.POST / "logoff")
      .header(cookieHeader)
      .out[Boolean]
  )

  val whoami = uefErrors(
    Endpoint(Method.GET / "me")
      .header(cookieHeader)
      .header(authHeader)
      .out[LoginResponse]
  )

  /* accounts */

  val listAccounts = uefErrors(
    Endpoint(Method.GET / "accounts")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[List[AccountResponse]]
  )

  val createAccount = uefErrors(
    Endpoint(Method.POST / "accounts")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[CreateAccountBody]
      .out[AccountResponse]
  )

  val updateAccount = uefErrors(
    Endpoint(Method.PUT / "accounts" / accParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[UpdateAccountBody]
      .out[AccountResponse]
  )

  val deleteAccount = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  /* users */

  val listUsers = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "users")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[List[UserResponse]]
  )

  val createUser = uefErrors(
    Endpoint(Method.POST / "accounts" / accParam / "users")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[CreateUserBody]
      .out[UserResponse]
  )

  val updateUser = uefErrors(
    Endpoint(Method.PUT / "accounts" / accParam / "users" / usrParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[UpdateUserBody]
      .out[UserResponse]
  )

  val deleteUser = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam / "users" / usrParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  val changePassword = uefErrors(
    Endpoint(Method.POST / "users" / "password" / "change")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[ChangePasswordBody]
      .out[Boolean]
  )

  val resetPassword = uefErrors(
    Endpoint(Method.POST / "users" / "password" / "reset")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[PasswordResetBody]
      .out[PasswordResetResponse]
  )

  val setPin = uefErrors(
    Endpoint(Method.POST / "users" / "pin")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[SetPinBody]
      .out[Boolean]
  )

  /* groups */

  private val accQuery = QueryCodec.query[Long]("acc").optional

  val listGroups = uefErrors(
    Endpoint(Method.GET / "apps" / appParam / "groups")
      .header(cookieHeader)
      .header(authHeader)
      .query(accQuery)
      .out[List[GroupResponse]]
  )

  val listGroupUsers = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "apps" / appParam / "groups" / grpParam / "users")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[UserResponse]]
  )

  val createGroup = uefErrors(
    Endpoint(Method.POST / "apps" / appParam / "groups")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[CreateGroupBody]
      .out[GroupResponse]
  )

  val deleteGroup = uefErrors(
    Endpoint(Method.DELETE / "apps" / appParam / "groups" / grpParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  /* applications — system-wide, no X-Admin-App needed (root-account only) */

  val listApplications = uefErrors(
    Endpoint(Method.GET / "applications")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[ApplicationResponse]]
  )

  val createApplication = uefErrors(
    Endpoint(Method.POST / "applications")
      .header(cookieHeader)
      .header(authHeader)
      .in[CreateApplicationBody]
      .out[ApplicationResponse]
  )

  val updateApplication = uefErrors(
    Endpoint(Method.PUT / "applications")
      .header(cookieHeader)
      .header(authHeader)
      .in[UpdateApplicationBody]
      .out[ApplicationResponse]
  )

  /* roles — read-only, system-wide (keyed by path app code, no X-Admin-App) */

  val listRoles = uefErrors(
    Endpoint(Method.GET / "apps" / appParam / "roles")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[RoleResponse]]
  )

  /* tenants — system-wide, no X-Admin-App needed (root-account only) */

  val listTenants = uefErrors(
    Endpoint(Method.GET / "tenants")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[TenantResponse]]
  )

  val createTenant = uefErrors(
    Endpoint(Method.POST / "tenants")
      .header(cookieHeader)
      .header(authHeader)
      .in[CreateTenantBody]
      .out[TenantResponse]
  )

  val updateTenant = uefErrors(
    Endpoint(Method.PUT / "tenants" / tnParam)
      .header(cookieHeader)
      .header(authHeader)
      .in[UpdateTenantBody]
      .out[TenantResponse]
  )

  val deleteTenant = uefErrors(
    Endpoint(Method.DELETE / "tenants" / tnParam)
      .header(cookieHeader)
      .header(authHeader)
      .out[Boolean]
  )

  /* identity providers (per account) */

  val listProviders = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "providers")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[List[ProviderResponse]]
  )

  val createProvider = uefErrors(
    Endpoint(Method.POST / "accounts" / accParam / "providers")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[CreateProviderBody]
      .out[ProviderResponse]
  )

  val updateProvider = uefErrors(
    Endpoint(Method.PUT / "accounts" / accParam / "providers" / prvParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[UpdateProviderBody]
      .out[ProviderResponse]
  )

  val deleteProvider = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam / "providers" / prvParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  /* api keys (service accounts per account) */

  val listApiKeys = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "api-keys")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[List[ApiKeyResponse]]
  )

  val issueApiKey = uefErrors(
    Endpoint(Method.POST / "accounts" / accParam / "api-keys")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .in[CreateApiKeyBody]
      .out[ApiKeyIssuedResponse]
  )

  val deleteApiKey = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam / "api-keys" / keyParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  /* application delete */

  val deleteApplication = uefErrors(
    Endpoint(Method.DELETE / "applications" / appParam)
      .header(cookieHeader)
      .header(authHeader)
      .out[Boolean]
  )

  /* account-apps management: enable/disable apps per account */

  val listAccountApps = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "apps")
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[List[ApplicationResponse]]
  )

  val linkAccountApp = uefErrors(
    Endpoint(Method.POST / "accounts" / accParam / "apps" / appParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  val unlinkAccountApp = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam / "apps" / appParam)
      .header(cookieHeader)
      .header(authHeader)
      .header(adminAppHeader)
      .out[Boolean]
  )

  val all: Seq[Endpoint[?, ?, ?, ?, AuthType.None]] = Seq(
    login, loginProvider, logoff, whoami,
    listAccounts, createAccount, updateAccount, deleteAccount,
    listUsers, createUser, updateUser, deleteUser, changePassword, resetPassword, setPin,
    listGroups, createGroup, deleteGroup, listGroupUsers,
    listApplications, createApplication, updateApplication, deleteApplication,
    listRoles,
    listTenants, createTenant, updateTenant, deleteTenant,
    listProviders, createProvider, updateProvider, deleteProvider,
    listApiKeys, issueApiKey, deleteApiKey,
    listAccountApps, linkAccountApp, unlinkAccountApp,
  )
}
