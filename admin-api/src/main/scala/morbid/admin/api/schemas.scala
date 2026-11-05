package morbid.admin.api

import morbid.domain.UserKind
import morbid.types.*
import zio.schema.Schema

object schemas {

  given Schema[Email]           = Schema[String].transform(Email.of          , Email.value)
  given Schema[Password]        = Schema[String].transform(Password.of       , Password.value)
  given Schema[Pin]             = Schema[String].transform(Pin.of            , Pin.value)
  given Schema[AccountName]     = Schema[String].transform(AccountName.of    , AccountName.value)
  given Schema[AccountCode]     = Schema[String].transform(AccountCode.of    , AccountCode.value)
  given Schema[AccountId]       = Schema[Long]  .transform(AccountId.of      , AccountId.value)
  given Schema[TenantId]        = Schema[Long]  .transform(TenantId.of       , TenantId.value)
  given Schema[TenantCode]      = Schema[String].transform(TenantCode.of     , TenantCode.value)
  given Schema[UserId]          = Schema[Long]  .transform(UserId.of         , UserId.value)
  given Schema[UserCode]        = Schema[String].transform(UserCode.of       , UserCode.value)
  given Schema[ApplicationId]   = Schema[Long]  .transform(ApplicationId.of  , ApplicationId.value)
  given Schema[ApplicationCode] = Schema[String].transform(ApplicationCode.of, ApplicationCode.value)
  given Schema[ApplicationName] = Schema[String].transform(ApplicationName.of, ApplicationName.value)
  given Schema[GroupId]         = Schema[Long]  .transform(GroupId.of        , GroupId.value)
  given Schema[GroupCode]       = Schema[String].transform(GroupCode.of      , GroupCode.value)
  given Schema[GroupName]       = Schema[String].transform(GroupName.of      , GroupName.value)
  given Schema[RoleId]          = Schema[Long]  .transform(RoleId.of         , RoleId.value)
  given Schema[RoleCode]        = Schema[String].transform(RoleCode.of       , RoleCode.value)
  given Schema[RoleName]        = Schema[String].transform(RoleName.of       , RoleName.value)
  given Schema[Link]            = Schema[String].transform(Link.of           , Link.value)
  given Schema[UserKind]        = Schema[String].transform(UserKind.valueOf  , _.toString)
}
