package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.Buttons
import medulla.utils.Signals
import morbid.admin.*
import morbid.domain.raw.AccountWithApps
import morbid.protocol.*
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object AccountsView {

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val columns = Seq(
      DataTable.Column[AccountWithApps](dict.columnName   , it => span(AccountName.value(it.account.name))),
      DataTable.Column[AccountWithApps](dict.columnId     , it => span(AccountId.value(it.account.id))),
      DataTable.Column[AccountWithApps](dict.columnCode   , it => span(cls("font-mono text-xs"), AccountCode.value(it.account.code))),
      DataTable.Column[AccountWithApps](dict.columnStatus , it => StatusLabel.render(it.account.active)),
      DataTable.Column[AccountWithApps](dict.columnApps   , it => Pills.of(it.apps.map(_.name).map(ApplicationName.value))),
      DataTable.Column[AccountWithApps](dict.columnActions, it =>
        div(
          cls("flex items-center gap-2"),
          button(cls("text-admin-muted hover:text-admin-text")    , MaterialIcon("edit", "text-lg")),
          button(cls("text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg")),
        )
      ),
    )

    def renderData(accounts: Seq[AccountWithApps], filter: String) = {
      DataTable.render(Signal.fromValue(accounts), columns, _.account.id)
    }

    val accounts = Var(Option.empty[Try[Seq[AccountWithApps]]])
    val filter   = Var("")

    val results = Signals.and(accounts, filter) {
      case (None                , _       ) => div(dict.loading)
      case (Some(Failure(err))  , _       ) => div(s"Load Error: ${err.getMessage}")
      case (Some(Success(items)), filterBy) => renderData(items, filterBy)
    }

    div(
      fetcher.execute(Endpoints.accounts(AllAccounts())).map(Some(_)) --> accounts,
      PageHeader.render(dict.accountsTitle, dict.accountsSubtitle, Buttons.primary.amend(dict.accountsNew)),
      child <-- results
    )
  }
}
