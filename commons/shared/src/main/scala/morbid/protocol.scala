package morbid.protocol

import morbid.types.{AccountId, ApplicationCode, ApplicationId, ApplicationName}
import zio.json.{DeriveJsonCodec, JsonCodec, jsonDiscriminator}

@jsonDiscriminator("type")
sealed trait GetAccountsRequest
case class AllAccounts()                               extends GetAccountsRequest
case class AccountsByApp(applicationId: ApplicationId) extends GetAccountsRequest

@jsonDiscriminator("type")
sealed trait GetApplicationsRequest
case class AllApplications() extends GetApplicationsRequest

@jsonDiscriminator("type")
sealed trait GetGroupsRequest
case class GroupsByApp      (application: ApplicationId)                     extends GetGroupsRequest
case class GroupsByAppAndAcc(application: ApplicationId, account: AccountId) extends GetGroupsRequest

case class CreateApplicationRequest(
  code: ApplicationCode,
  name: ApplicationName,
)

case class UpdateApplicationRequest(
  id     : ApplicationId,
  active : Boolean,
  name   : ApplicationName,
)

case class DeleteApplicationRequest(id: ApplicationId)

given JsonCodec[CreateApplicationRequest] = DeriveJsonCodec.gen
given JsonCodec[UpdateApplicationRequest] = DeriveJsonCodec.gen
given JsonCodec[GetAccountsRequest]       = DeriveJsonCodec.gen
given JsonCodec[GetApplicationsRequest]   = DeriveJsonCodec.gen
given JsonCodec[GetGroupsRequest]         = DeriveJsonCodec.gen
