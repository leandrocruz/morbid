package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import morbid.admin.*
import morbid.domain.raw.{AccountWithApps, RawAccount, RawGroup}
import morbid.protocol.*
import morbid.types.*
import morbid.ui.DataTable

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object ApplicationGroupsView {
  def render(app: ApplicationId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def toAccountId(value: String) = Try(value.toLong).toOption.map(AccountId.of)

    def renderGroups(id: AccountId) = GroupsView.render(app, id)

    val acc      = Var(Option.empty[AccountId])
    val accounts = Var(Option.empty[Try[Seq[AccountWithApps]]])

    div(
      fetcher.execute(Endpoints.accounts(AccountsByApp(app))).map(Some(_)) --> accounts,
      s"Grupos do app ${app}. Escolha a conta para continuar",
      select(
        cls("text-sm border border-admin-border rounded-sm px-2 py-1 bg-white"),
        children <-- accounts.signal.map {
          case None                   => Seq(option("Carregando"))
          case Some(Failure(err))     => Seq(option(s"Erro: ${err.getMessage}"))
          case Some(Success(options)) => Seq(option(value("0"), "--")) ++ options.map(op => option(value(AccountId.value(op.account.id).toString), AccountName.value(op.account.name)))
        },
        controlled(
          value <-- acc.signal.map(_.map(_.toString).getOrElse("0")),
          onChange.mapToValue.map(toAccountId) --> acc
        )
      ),
      child.maybe <-- acc.signal.map(_.map(renderGroups))
    )
  }
}

object AccountGroupsView {
  def render(acc: AccountId)(using dict: Dictionary): HtmlElement = {
    div(
      s"Grupos do conta ${acc}. Escolha o app para continuar",
    )
  }
}

object GroupsView {
  def render(app: ApplicationId, acc: AccountId)(using dict: Dictionary, fetcher: Fetcher) = {

    val columns = Seq(
      DataTable.Column[RawGroup](dict.columnName , it => span(GroupName.value(it.name))),
      DataTable.Column[RawGroup](dict.columnRoles, it => Pills.of(it.roles.map(r => RoleName.value(r.name))))
    )

    val groups = Var(Option.empty[Try[Seq[RawGroup]]])

    div(
      fetcher.execute(Endpoints.groups(GroupsByAppAndAcc(app, acc))).map(Some(_)) --> groups,
      s"Grupos do app ${app} para a conta ${acc}",
      child <-- groups.signal.map {
        case None                  => div("Carregando")
        case Some(Failure(err))    => div(s"Erro ao carregar: ${err.getMessage}")
        case Some(Success(result)) => DataTable.simple(columns, _.id).render(Signal.fromValue(result))
      }
    )
  }
}

