package morbid.admin.views

import com.raquo.laminar.api.L.*
import morbid.admin.Dictionary
import org.scalajs.dom.console

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
  def render(isActive: Boolean)(using dict: Dictionary): HtmlElement = {
    span(
      cls("label"),
      cls(if isActive then "active" else "inactive"),
      if isActive then dict.active else dict.inactive
    )
  }
}

object Pills {
  def of(pills: Seq[Modifier[HtmlElement]]) = div(cls("flex gap-2"), pills.map(p => span(cls("label bg-green-300"), p)))
}

object DataTable {

  case class Column[T](
    header  : String,
    render  : T => HtmlElement,
    cls     : String = ""
  )

  def noHighlight[T](t: T): Signal[Boolean] = Signal.fromValue(false)

  def render[T, K](
    items     : Signal[Seq[T]],
    columns   : Seq[Column[T]],
    key       : T => K
  )(using dict: Dictionary): HtmlElement = {

    def renderRow(key: K, initial: T, item: Signal[T]): HtmlElement = {

      def render(column: Column[T])(it: T) = {
        console.log(s"Render Col (${column.header}): $it")
        column.render(it)
      }

      console.log(s"Render Row ${key} / ${initial}")
      tr(
        //cls.toggle("highlight") <-- highlight(initial),
        columns.map { col =>
          td(cls(col.cls), child <-- item.map(render(col)))
        }
      )
    }

    val rows  = items.split(key)(renderRow)
    val empty = items.map(_.isEmpty)

    div(
      cls("admin-card"),
      table(
        cls("admin-table"),
        thead(tr(columns.map(col => th(cls(col.cls), col.header)))),
        tbody(
          children <-- rows,
          child.maybe <-- empty.map {
            case true  => Some(tr(td(colSpan(columns.size), cls("text-center py-8 text-admin-muted"), dict.noRecords)))
            case false => None
          }
        )
      ),
      div(
        cls("flex items-center justify-between px-4 py-3 text-sm text-admin-muted"),
        child.text <-- items.map(items => dict.showing(items.size))
      )
    )
  }
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
