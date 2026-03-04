package morbid.admin

import medulla.fetch.FetchRequest
import morbid.types.*
import morbid.domain.raw.*
import codec.given

object Endpoints {

  private val AppCode = "presto"

  def applications = FetchRequest(s"/applications").get[Seq[RawApplicationDetails]]
  def accounts     = FetchRequest(s"/app/$AppCode/manager/accounts").get[Seq[RawAccount]]
  def users        = FetchRequest(s"/app/$AppCode/users").get[Seq[RawUserEntry]]
  def groups       = FetchRequest(s"/app/$AppCode/groups").get[Seq[RawGroup]]
  def roles        = FetchRequest(s"/app/$AppCode/roles").get[Seq[RawRole]]
}
