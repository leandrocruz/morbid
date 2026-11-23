package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.table.DataTable
import morbid.admin.*
import morbid.admin.api.*
import morbid.admin.codec.given
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

/** Enable/disable apps on an account. Shows every application in the system
  * with a toggle that creates/removes the `account_to_app` link via the admin-api. */
object AccountAppsView {

  private case class State(
    all    : Seq[ApplicationResponse],
    linked : Set[ApplicationCode],
  )

  def render(acc: AccountId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val data    = Var(Option.empty[Try[State]])
    val error   = Var(Option.empty[String])
    val busy    = Var(Set.empty[ApplicationCode])

    val loadFlow: EventStream[Try[State]] =
      fetcher.execute(Endpoints.listApplications).combineWith(
        fetcher.execute(Endpoints.listAccountApps(acc))
      ).map { (allTry, linkedTry) =>
        for
          all    <- allTry
          linked <- linkedTry
        yield State(all.toSeq.sortBy(a => ApplicationName.value(a.name)), linked.map(_.code).toSet)
      }

    val toggleBus = EventBus[(ApplicationCode, Boolean)]()

    val toggleFlow: EventStream[(ApplicationCode, Boolean, Try[Boolean])] =
      toggleBus.events.flatMapMerge { case (code, enable) =>
        busy.update(_ + code)
        error.set(None)
        val call =
          if enable then fetcher.execute(Endpoints.linkAccountApp  (acc, code))
          else           fetcher.execute(Endpoints.unlinkAccountApp(acc, code))
        call.map(result => (code, enable, result))
      }

    val toggleObserver: Observer[(ApplicationCode, Boolean, Try[Boolean])] = Observer {
      case (code, enable, result) =>
        busy.update(_ - code)
        result match
          case Success(_) =>
            data.update {
              case Some(Success(st)) =>
                val next = if enable then st.linked + code else st.linked - code
                Some(Success(st.copy(linked = next)))
              case other => other
            }
          case Failure(err) => error.set(Some(err.getMessage))
    }

    def toggleFor(app: ApplicationResponse, linked: Set[ApplicationCode], admin: Boolean): HtmlElement = {
      val isOn    = linked.contains(app.code)
      val pending = busy.signal.map(_.contains(app.code))
      input(
        typ("checkbox"),
        cls("h-4 w-4 accent-admin-accent cursor-pointer"),
        checked(isOn),
        disabled <-- pending.map(_ || !admin),
        onInput.mapToChecked --> { next => toggleBus.emit((app.code, next)) },
      )
    }

    val rows = data.signal.map {
      case Some(Success(st)) => st.all.map(a => (a, st.linked))
      case _                 => Seq.empty[(ApplicationResponse, Set[ApplicationCode])]
    }

    val adminSig = Session.isAdmin

    def columns = Seq(
      DataTable.Column[(ApplicationResponse, Set[ApplicationCode])](dict.columnName,   row => span(ApplicationName.value(row._1.name))),
      DataTable.Column[(ApplicationResponse, Set[ApplicationCode])](dict.columnCode,   row => span(cls("font-mono text-xs"), ApplicationCode.value(row._1.code))),
      DataTable.Column[(ApplicationResponse, Set[ApplicationCode])](dict.columnStatus, row => StatusLabel.render(row._1.active)),
      DataTable.Column[(ApplicationResponse, Set[ApplicationCode])](dict.accountAppsEnabled, row =>
        div(cls("flex items-center"), child <-- adminSig.map(a => toggleFor(row._1, row._2, a)))
      ),
    )

    val tbl = DataTable.simple(columns, _._1.id)

    val status = data.signal.map {
      case None               => (false, Some(div(dict.loading)))
      case Some(Failure(err)) => (false, Some(div(s"Load Error: ${err.getMessage}")))
      case _                  => (true , None)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    val errorView = child.maybe <-- error.signal.map(_.map(msg =>
      div(cls("text-sm text-admin-error-fg mb-2"), msg)
    ))

    div(
      loadFlow.map(Some(_)) --> data,
      toggleFlow --> toggleObserver,
      PageHeader.render(dict.accountAppsTitle, s"${dict.accountAppsSubtitle} (acc #${AccountId.value(acc)})"),
      errorView,
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
    )
  }
}
