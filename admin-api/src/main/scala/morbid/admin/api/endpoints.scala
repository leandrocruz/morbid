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
  */
object endpoints {

  private val accParam = string("acc")
  private val usrParam = string("usr")
  private val grpParam = string("grp")
  private val appParam = string("app")

  private val cookieHeader = HeaderCodec.headerAs[String]("cookie").optional
  private val authHeader   = HeaderCodec.headerAs[AuthorizationHeader]("authorization").optional

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
      .out[List[AccountResponse]]
  )

  val createAccount = uefErrors(
    Endpoint(Method.POST / "accounts")
      .header(cookieHeader)
      .header(authHeader)
      .in[CreateAccountBody]
      .out[AccountResponse]
  )

  val updateAccount = uefErrors(
    Endpoint(Method.PUT / "accounts" / accParam)
      .header(cookieHeader)
      .header(authHeader)
      .in[UpdateAccountBody]
      .out[AccountResponse]
  )

  val deleteAccount = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam)
      .header(cookieHeader)
      .header(authHeader)
      .out[Boolean]
  )

  /* users */

  val listUsers = uefErrors(
    Endpoint(Method.GET / "accounts" / accParam / "users")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[UserResponse]]
  )

  val createUser = uefErrors(
    Endpoint(Method.POST / "accounts" / accParam / "users")
      .header(cookieHeader)
      .header(authHeader)
      .in[CreateUserBody]
      .out[UserResponse]
  )

  val updateUser = uefErrors(
    Endpoint(Method.PUT / "accounts" / accParam / "users" / usrParam)
      .header(cookieHeader)
      .header(authHeader)
      .in[UpdateUserBody]
      .out[UserResponse]
  )

  val deleteUser = uefErrors(
    Endpoint(Method.DELETE / "accounts" / accParam / "users" / usrParam)
      .header(cookieHeader)
      .header(authHeader)
      .out[Boolean]
  )

  val changePassword = uefErrors(
    Endpoint(Method.POST / "users" / "password" / "change")
      .header(cookieHeader)
      .header(authHeader)
      .in[ChangePasswordBody]
      .out[Boolean]
  )

  val resetPassword = uefErrors(
    Endpoint(Method.POST / "users" / "password" / "reset")
      .header(cookieHeader)
      .header(authHeader)
      .in[PasswordResetBody]
      .out[PasswordResetResponse]
  )

  val setPin = uefErrors(
    Endpoint(Method.POST / "users" / "pin")
      .header(cookieHeader)
      .header(authHeader)
      .in[SetPinBody]
      .out[Boolean]
  )

  /* groups */

  val listGroups = uefErrors(
    Endpoint(Method.GET / "apps" / appParam / "groups")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[GroupResponse]]
  )

  val createGroup = uefErrors(
    Endpoint(Method.POST / "apps" / appParam / "groups")
      .header(cookieHeader)
      .header(authHeader)
      .in[CreateGroupBody]
      .out[GroupResponse]
  )

  val deleteGroup = uefErrors(
    Endpoint(Method.DELETE / "apps" / appParam / "groups" / grpParam)
      .header(cookieHeader)
      .header(authHeader)
      .out[Boolean]
  )

  /* applications */

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

  /* roles */

  val listRoles = uefErrors(
    Endpoint(Method.GET / "apps" / appParam / "roles")
      .header(cookieHeader)
      .header(authHeader)
      .out[List[RoleResponse]]
  )

  val all: Seq[Endpoint[?, ?, ?, ?, AuthType.None]] = Seq(
    login, loginProvider, logoff, whoami,
    listAccounts, createAccount, updateAccount, deleteAccount,
    listUsers, createUser, updateUser, deleteUser, changePassword, resetPassword, setPin,
    listGroups, createGroup, deleteGroup,
    listApplications, createApplication, updateApplication,
    listRoles,
  )
}
