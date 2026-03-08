package morbid.admin.views

import com.raquo.laminar.api.L
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
