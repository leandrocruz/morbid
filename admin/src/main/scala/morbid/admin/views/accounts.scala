package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.ui.Buttons
import morbid.admin.*
import morbid.types.*
import morbid.domain.raw.RawAccount

object AccountsView {

  def render(using dict: Dictionary): HtmlElement = {

    val accounts     = Var(Seq.empty[RawAccount])
    val searchFilter = Var("")

    val filtered = accounts.signal.combineWith(searchFilter.signal).map { (items, filter) =>
      if filter.isEmpty then items
      else items.filter(a => AccountName.value(a.name).toLowerCase.contains(filter.toLowerCase))
    }

    val columns = Seq(
      DataTable.Column[RawAccount](dict.columnName,   a => span(AccountName.value(a.name))),
      DataTable.Column[RawAccount](dict.columnCode,   a => span(cls("font-mono text-xs"), AccountCode.value(a.code))),
      DataTable.Column[RawAccount](dict.columnStatus, a => StatusLabel.render(a.active)),
      DataTable.Column[RawAccount](dict.columnActions, a =>
        div(
          cls("flex items-center gap-2"),
          button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("edit", "text-lg")),
          button(cls("text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg")),
        )
      ),
    )

    div(
      PageHeader.render(
        dict.accountsTitle,
        dict.accountsSubtitle,
        Buttons.primary.amend(dict.accountsNew)
      ),
      div(
        cls("mb-4"),
        SearchBox.render(dict.search, v => searchFilter.set(v))
      ),
      DataTable.render(filtered, columns),
    )
  }
}
