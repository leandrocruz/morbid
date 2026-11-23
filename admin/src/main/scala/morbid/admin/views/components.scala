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

object StatusSummary {
  def render(totals: Signal[(Int, Int)])(using dict: Dictionary): HtmlElement = {
    def chip(colorClasses: String, label: String, count: Signal[Int]) =
      div(
        cls(s"inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm $colorClasses"),
        span(cls("font-semibold text-base"), child.text <-- count.map(_.toString)),
        span(label),
      )

    val active   = totals.map(_._1)
    val inactive = totals.map(_._2)
    val total    = totals.map { case (a, i) => a + i }

    div(
      cls("flex flex-wrap items-center gap-3 mb-4"),
      chip("bg-green-100 text-green-800"             , dict.summaryActive  , active),
      chip("bg-gray-100 text-gray-700"               , dict.summaryInactive, inactive),
      chip("bg-admin-primary/10 text-admin-primary"  , dict.summaryTotal   , total),
    )
  }
}
