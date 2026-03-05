package morbid.admin

import medulla.fetch.{FetchRequest, RequestBuilder}
import morbid.domain.raw.*
import codec.given
import morbid.protocol.{given, *}
import morbid.types.*

object Endpoints {

  private val AppCode = "presto"

  def accounts          (req: GetAccountsRequest)       = FetchRequest("/accounts")     .post[GetAccountsRequest    , Seq[AccountWithApps]]       (req)
  def applicationUpdate (req: UpdateApplicationRequest) = FetchRequest("/application")  .post[UpdateApplicationRequest, RawApplicationDetails]    (req)
  def applications      (req: GetApplicationsRequest)   = FetchRequest("/applications") .post[GetApplicationsRequest, Seq[RawApplicationDetails]] (req)
  def groups            (req: GetGroupsRequest)         = FetchRequest("/groups")       .post[GetGroupsRequest      , Seq[RawGroup]]              (req)
  def roles        = FetchRequest(s"/app/$AppCode/roles").get[Seq[RawRole]]
  def users        = FetchRequest(s"/app/$AppCode/users").get[Seq[RawUserEntry]]
}
