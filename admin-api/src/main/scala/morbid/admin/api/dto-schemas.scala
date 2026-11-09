package morbid.admin.api

import morbid.admin.api.schemas.given
import zio.schema.{DeriveSchema, Schema}

/** zio-schema instances for the DTOs declared in morbid-commons (admin-api.scala).
  * Kept here because the shared module (JS + JVM) doesn't depend on zio-schema.
  */
object dtoSchemas {

  given Schema[LoginMode]              = DeriveSchema.gen
  given Schema[LoginRequest]           = DeriveSchema.gen
  given Schema[LoginResponse]          = DeriveSchema.gen
  given Schema[GetProviderRequest]     = DeriveSchema.gen
  given Schema[GetProviderResponse]    = DeriveSchema.gen
  given Schema[AccountResponse]        = DeriveSchema.gen
  given Schema[CreateAccountBody]      = DeriveSchema.gen
  given Schema[UpdateAccountBody]      = DeriveSchema.gen
  given Schema[UserResponse]           = DeriveSchema.gen
  given Schema[CreateUserBody]         = DeriveSchema.gen
  given Schema[UpdateUserBody]         = DeriveSchema.gen
  given Schema[ChangePasswordBody]     = DeriveSchema.gen
  given Schema[SetPinBody]             = DeriveSchema.gen
  given Schema[PasswordResetBody]      = DeriveSchema.gen
  given Schema[PasswordResetResponse]  = DeriveSchema.gen
  given Schema[GroupResponse]          = DeriveSchema.gen
  given Schema[CreateGroupBody]        = DeriveSchema.gen
  given Schema[ApplicationResponse]    = DeriveSchema.gen
  given Schema[CreateApplicationBody]  = DeriveSchema.gen
  given Schema[UpdateApplicationBody]  = DeriveSchema.gen
  given Schema[RoleResponse]           = DeriveSchema.gen
  given Schema[TenantResponse]         = DeriveSchema.gen
  given Schema[CreateTenantBody]       = DeriveSchema.gen
  given Schema[UpdateTenantBody]       = DeriveSchema.gen
  given Schema[ProviderResponse]       = DeriveSchema.gen
  given Schema[CreateProviderBody]     = DeriveSchema.gen
  given Schema[UpdateProviderBody]     = DeriveSchema.gen
  given Schema[ApiKeyResponse]         = DeriveSchema.gen
  given Schema[CreateApiKeyBody]       = DeriveSchema.gen
  given Schema[ApiKeyIssuedResponse]   = DeriveSchema.gen
}
