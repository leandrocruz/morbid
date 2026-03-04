package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.utils.{Mediator, Signals}
import morbid.admin.*
import morbid.types.*
import morbid.domain.raw.RawApplicationDetails

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object ApplicationsView {


  def render(fetcher: Fetcher)(using dict: Dictionary): HtmlElement = {

    val columns = Seq(
      DataTable.Column[RawApplicationDetails](dict.columnName, a => span(ApplicationName.value(a.name))),
      DataTable.Column[RawApplicationDetails](dict.columnCode, a => span(cls("font-mono text-xs"), ApplicationCode.value(a.code))),
      DataTable.Column[RawApplicationDetails](dict.columnStatus, a => StatusLabel.render(a.deleted.isEmpty)),
      DataTable.Column[RawApplicationDetails](dict.columnActions, a =>
        div(
          cls("flex items-center gap-2"),
          button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("edit", "text-lg")),
          button(cls("text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg")),
        )
      ),
    )

    val apps         = Var(Option.empty[Try[Seq[RawApplicationDetails]]])
    val searchFilter = Var("")

    val results = Signals.and(apps, searchFilter) {
      case (None                , _     ) => div("loading")
      case (Some(Failure(err))  , _     ) => div(s"Load Error: ${err.getMessage}")
      case (Some(Success(items)), filter) =>
        val filtered = items.filter(a => ApplicationName.value(a.name).toLowerCase.contains(filter.toLowerCase))
        DataTable.render(Signal.fromValue(filtered), columns)
    }

    div(
      fetcher.execute(Endpoints.applications).map(Some(_)) --> apps,
      PageHeader.render(
        dict.appsTitle,
        dict.appsSubtitle,
      ),
      div(
        cls("mb-4"),
        SearchBox.render(dict.search, v => searchFilter.set(v))
      ),
      child <-- results
    )
  }
}
