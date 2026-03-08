package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.ui.Buttons
import morbid.admin.*
import morbid.types.*
import morbid.domain.raw.RawUserEntry
import medulla.ui.table.DataTable

object UsersView {

  def render(using dict: Dictionary): HtmlElement = {

    val users        = Var(Seq.empty[RawUserEntry])
    val searchFilter = Var("")

    val filtered = users.signal.combineWith(searchFilter.signal).map { (items, filter) =>
      if filter.isEmpty then items
      else items.filter(u => Email.value(u.email).toLowerCase.contains(filter.toLowerCase))
    }

    val columns = Seq(
      DataTable.Column[RawUserEntry](dict.columnEmail,  u => span(Email.value(u.email))),
      DataTable.Column[RawUserEntry](dict.columnCode,   u => span(cls("font-mono text-xs"), UserCode.value(u.code))),
      DataTable.Column[RawUserEntry](dict.columnStatus, u => StatusLabel.render(u.active)),
      DataTable.Column[RawUserEntry](dict.columnActions, u =>
        div(
          cls("flex items-center gap-2"),
          button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("edit", "text-lg")),
          button(cls("text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg")),
        )
      ),
    )

    div(
      PageHeader.render(
        dict.usersTitle,
        dict.usersSubtitle,
        Buttons.primary.amend(dict.usersNew)
      ),
      div(
        cls("mb-4"),
        SearchBox.render(dict.search, v => searchFilter.set(v))
      ),
      DataTable.simple(columns, _.id).render(Signal.fromValue(Seq.empty)),
    )
  }
}
