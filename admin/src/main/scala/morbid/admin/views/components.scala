package morbid.admin.views

import com.raquo.laminar.api.L.*
import morbid.admin.Dictionary

object PageHeader {

  def render(title: String, subtitle: String, actions: HtmlElement*): HtmlElement =
    div(
      cls("page-header"),
      div(
        cls("info"),
        h1(title),
        p(subtitle)
      ),
      div(
        cls("flex items-center gap-2"),
        actions
      )
    )
}

object StatusLabel {

  def render(isActive: Boolean)(using dict: Dictionary): HtmlElement =
    span(
      cls("status-label"),
      cls(if isActive then "active" else "inactive"),
      if isActive then dict.active else dict.inactive
    )
}

object DataTable {

  case class Column[T](
    header  : String,
    render  : T => HtmlElement,
    cls     : String = ""
  )

  def render[T](
    items   : Signal[Seq[T]],
    columns : Seq[Column[T]],
  )(using dict: Dictionary): HtmlElement =
    div(
      cls("admin-card"),
      table(
        cls("admin-table"),
        thead(
          tr(
            columns.map(col =>
              th(cls(col.cls), col.header)
            )
          )
        ),
        tbody(
          children <-- items.map { rows =>
            if rows.isEmpty then
              Seq(tr(td(colSpan(columns.size), cls("text-center py-8 text-admin-muted"), dict.noRecords)))
            else
              rows.map { item =>
                tr(
                  columns.map(col =>
                    td(cls(col.cls), col.render(item))
                  )
                )
              }
          }
        )
      ),
      div(
        cls("flex items-center justify-between px-4 py-3 text-sm text-admin-muted"),
        child.text <-- items.map(rows => dict.showing(rows.size))
      )
    )
}

object SearchBox {

  def render(hint: String, onSearch: String => Unit): HtmlElement =
    div(
      cls("relative"),
      span(
        cls("material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-admin-muted text-lg"),
        "search"
      ),
      input(
        cls("medulla pl-10"),
        typ("text"),
        placeholder(hint),
        onInput.mapToValue --> { v => onSearch(v) }
      )
    )
}

object MaterialIcon {
  def apply(name: String, extraCls: String = ""): HtmlElement =
    span(cls(s"material-symbols-outlined $extraCls"), name)
}
