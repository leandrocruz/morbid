package morbid.commands

import zio.*

import morbid.types.*
import morbid.domain.*
import morbid.domain.raw.*
import java.time.LocalDateTime

sealed trait Command[R]

case class FindApplications(account: AccountCode) extends Command[Seq[RawApplicationDetails]]

case class FindApplicationDetails(
  application: ApplicationCode
) extends Command[Option[RawApplicationDetails]]

case class FindApplication(
  account     : AccountCode,
  application : ApplicationCode
) extends Command[Option[RawApplication]]

case class LinkUsersToGroup(
  application : ApplicationId,
  group       : GroupId,
  users       : Seq[UserId]
) extends Command[Unit]

case class UnlinkUsersFromGroup(
  application: ApplicationId,
  group      : GroupId,
  users      : Seq[UserId]
) extends Command[Unit]

case class FindGroups(
  account : AccountCode,
  apps    : Seq[ApplicationCode],
  filter  : Seq[GroupCode] = Seq.empty
) extends Command[Map[ApplicationCode, Seq[RawGroup]]]

case class FindUsersInGroup(
  account : AccountCode,
  app     : ApplicationCode,
  group   : Option[GroupCode] = None
) extends Command[Seq[RawUserEntry]]

case class FindAccountsByApp(app: ApplicationCode) extends Command[Seq[RawAccount]]
case class FindUsersByApp   (app: ApplicationCode) extends Command[Seq[RawUserData]]

case class FindUsersByCode(account: AccountId, codes: Seq[UserCode]) extends Command[Seq[RawUserEntry]]
case class FindUserById(id: UserId) extends Command[Option[RawUser]]
case class FindUserByEmail(email: Email) extends Command[Option[RawUser]]
case class GetUserPin(user: UserId) extends Command[Option[Sha256Hash]]
case class DefineUserPin(user: UserId, pin: Sha256Hash) extends Command[Unit]

case class StoreAccount(
  id     : AccountId  , // Maybe 0
  tenant : TenantId   ,
  code   : AccountCode,
  name   : AccountName,
  active : Boolean,
  update : Boolean,
) extends Command[RawAccount]

case class StoreUser(
  id      : UserId, // maybe 0
  email   : Email,
  code    : UserCode, // From firebase
  account : RawAccount,
  kind    : Option[UserKind] = None,
  update  : Boolean, //TODO: remove this as soon as we migrate all users from legacy,
  active  : Boolean,
) extends Command[RawUserEntry]

case class StoreGroup(
  account     : AccountId,
  accountCode : AccountCode,
  application : RawApplication,
  group       : RawGroup,
  users       : Seq[UserCode],
  roles       : Seq[RoleCode]
) extends Command[RawGroup]

case class LinkAccountToApp(
  acc: AccountId,
  app: ApplicationId,
) extends Command[Unit]

case class LinkGroupToRoles(
  group : GroupId,
  roles : Seq[RoleId]
) extends Command[Unit]

case class UnlinkGroupFromRoles(
  group : GroupId,
  roles : Seq[RoleId]
) extends Command[Unit]

case class FindRoles(
  account : AccountCode,
  app     : ApplicationCode
) extends Command[Seq[RawRole]]

case class FindAccountByProvider(code: ProviderCode) extends Command[Option[RawAccount]]
case class FindAccountByCode    (code: AccountCode)  extends Command[Option[RawAccount]]
case class FindAccountById      (id: AccountId)      extends Command[Option[RawAccount]]

case class FindProviderByAccount(account: AccountId)                      extends Command[Option[RawIdentityProvider]]
case class FindProviderByDomain(domain: Domain, code: Option[TenantCode]) extends Command[Option[RawIdentityProvider]]

case class UsersByAccount(app: ApplicationCode, account: AccountId) extends Command[Seq[RawUserEntry]]
case class UserExists(code: UserCode) extends Command[Boolean]

case class RemoveAccount (id: AccountId)                                       extends Command[Unit]
case class RemoveUser    (acc: AccountId, code: UserCode)                      extends Command[Long]
case class RemoveGroup   (acc: AccountId, app: ApplicationId, code: GroupCode) extends Command[Long]