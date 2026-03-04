package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.ui.Buttons
import morbid.admin.*
import morbid.types.*
import morbid.domain.raw.RawGroup

object GroupsView {

  def render(using dict: Dictionary): HtmlElement = {

    val groups       = Var(Seq.empty[RawGroup])
    val searchFilter = Var("")

    val filtered = groups.signal.combineWith(searchFilter.signal).map { (items, filter) =>
      if filter.isEmpty then items
      else items.filter(g => GroupName.value(g.name).toLowerCase.contains(filter.toLowerCase))
    }

    val columns = Seq(
      DataTable.Column[RawGroup](dict.columnName, g => span(GroupName.value(g.name))),
      DataTable.Column[RawGroup](dict.columnCode, g => span(cls("font-mono text-xs"), GroupCode.value(g.code))),
      DataTable.Column[RawGroup](dict.columnActions, g =>
        div(
          cls("flex items-center gap-2"),
          button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("edit", "text-lg")),
          button(cls("text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg")),
        )
      ),
    )

    div(
      PageHeader.render(
        dict.groupsTitle,
        dict.groupsSubtitle,
        Buttons.primary.amend(dict.groupsNew)
      ),
      div(
        cls("mb-4"),
        SearchBox.render(dict.search, v => searchFilter.set(v))
      ),
      DataTable.render(filtered, columns),
    )
  }
}
