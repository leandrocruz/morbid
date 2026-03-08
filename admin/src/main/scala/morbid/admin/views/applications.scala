package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.{Buttons, Input}
import medulla.utils.Mediator
import morbid.admin.*
import morbid.converters.given
import morbid.domain.raw.RawApplicationDetails
import morbid.protocol.{AllApplications, UpdateApplicationRequest}
import morbid.types.*
import medulla.ui.table.DataTable

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.util.{Failure, Success, Try}

object ApplicationsView {

  sealed trait CrudEvent
  case class Created(item: RawApplicationDetails) extends CrudEvent
  case class Updated(item: RawApplicationDetails) extends CrudEvent
  case class Deleted(id: ApplicationId)           extends CrudEvent

  private sealed trait ModalMode
  private case object Closed extends ModalMode
  private case class EditMode  (app: RawApplicationDetails) extends ModalMode
  private case class DeleteMode(app: RawApplicationDetails) extends ModalMode

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def columns(mode: Var[ModalMode]) = {
      Seq(
        DataTable.Column[RawApplicationDetails](dict.columnName    , it => span(ApplicationName.value(it.name))),
        DataTable.Column[RawApplicationDetails](dict.columnCode    , it => span(cls("font-mono text-xs"), ApplicationCode.value(it.code))),
        DataTable.Column[RawApplicationDetails](dict.columnStatus  , it => StatusLabel.render(it.active)),
        DataTable.Column[RawApplicationDetails](dict.columnGroups  , it => Pills.of(Seq(a(dict.groups, AdminRouter.instance.linkTo(GroupsPage(it.id)))))),
        DataTable.Column[RawApplicationDetails](dict.columnActions , it =>
          div(
            cls("flex items-center gap-2"),
            button(cls("cursor-pointer text-admin-muted hover:text-admin-text"),     MaterialIcon("edit", "text-lg"),   onClick.mapTo(EditMode(it))   --> mode),
            button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode),
          )
        ),
      )
    }

    def rowsGiven(tbl: DataTable.Table[ApplicationId, RawApplicationDetails])(changes: Seq[CrudEvent], maybe: Option[Try[Seq[RawApplicationDetails]]]): Seq[RawApplicationDetails] = {
      def applyChanges(items: Seq[RawApplicationDetails]) = {
        changes.foldLeft(items) { (buffer, change) =>
          change match
            case Deleted(id)   => buffer.filterNot(_.id == id)
            case Created(item) => buffer :+ item
            case Updated(item) =>
              tbl.row(item.id).foreach { row =>
                row.highlight(true)
                js.timers.setTimeout(1500)({
                  row.highlight(false)
                  //row.disable(true)
                })
              }
              buffer.filterNot(_.id == item.id) :+ item
        }
      }

      maybe match
        case Some(Success(items)) => if(changes.isEmpty) items else applyChanges(items)
        case _                    => Seq.empty
    }

    val data    = Var(Option.empty[Try[Seq[RawApplicationDetails]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val rows    = changes.combineWith(data).map(rowsGiven(tbl)).map(_.sortBy(_.name))
    val opened  = mode.signal.map {
      case Closed => false
      case _      => true
    }

    val status = data.signal.map {
      case None               => (false, Some(div(dict.loading)))
      case Some(Failure(err)) => (false, Some(div(s"Load Error: ${err.getMessage}")))
      case _                  => (true , None)
    }

    val modalContent = mode.signal.map {
      case Closed          => div()
      case EditMode(app)   => renderEditModal  (app, mode, events)
      case DeleteMode(app) => renderDeleteModal(app, mode, events)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(
        cls("admin-card"),
        tbl.render(rows)
      )
    }

    div(
      fetcher.execute(Endpoints.applications(AllApplications())).map(Some(_)) --> data,
      PageHeader.render(dict.appsTitle, dict.appsSubtitle),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def renderEditModal(
    app    : RawApplicationDetails,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val name   = InputVar.of[ApplicationName](app.name)
    val active = InputVar.of[Boolean](app.active)

    val req = InputVar.combine(Failure(Exception("ERRO")))(name.must, active.must) { (theName, isActive) =>
      ApplicationName.value(theName) match
        case "xxx" => Failure(Exception("BAD NAME"))
        case _     => Success(UpdateApplicationRequest(app.id, isActive, theName))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.applicationUpdate(r)))

    div(
      med.wire,
      med.onlySuccesses.map(Updated(_)) --> events,
      med.onlySuccesses.mapTo(Closed) --> mode,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.edit),
        button(
          cls("text-admin-muted hover:text-admin-text"),
          MaterialIcon("close"),
          onClick.mapTo(Closed) --> mode
        )
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode),
          div(cls("font-mono text-sm text-admin-muted bg-gray-50 rounded px-3 py-2"), ApplicationCode.value(app.code))
        ),
        div(
          label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName),
          Input.basic(name)
        ),
        div(
          cls("flex items-center gap-3"),
          Input.checkbox(active),
//          input(
//            typ("checkbox"),
//            cls("w-4 h-4 accent-admin-accent"),
//            checked(activeVar.now()),
//            onChange.mapToChecked --> activeVar
//          ),
          label(cls("text-sm text-admin-text"), dict.active)
        ),
      ),
      child <-- med.onlyErrors.map(err => div(s"ERRO: ${err.getMessage}")),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(
          dict.cancel,
          disabled <-- med.disabled,
          onClick.mapTo(Closed) --> mode
        ),
        Buttons.primary.amend(
          dict.save,
          disabled <-- med.disabled,
          onClick.mapToUnit --> med.trigger
        ),
      )
    )
  }

  private def renderDeleteModal(
    app    : RawApplicationDetails,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {
    div(
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-error-fg"), dict.deleteTitle),
        button(
          cls("text-admin-muted hover:text-admin-text"),
          MaterialIcon("close"),
          onClick.mapTo(Closed) --> mode
        )
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          cls("flex items-center gap-3 p-4 bg-red-50 rounded-lg"),
          MaterialIcon("warning", "text-admin-error-fg text-2xl"),
          p(cls("text-sm text-admin-text"), dict.deleteMessage(ApplicationName.value(app.name)))
        ),
        div(
          label(cls("block text-sm font-medium text-admin-muted mb-1"), dict.columnCode),
          div(cls("font-mono text-sm text-admin-muted"), ApplicationCode.value(app.code))
        ),
      ),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.cancel, onClick.mapTo(Closed) --> mode),
        Buttons.primary.amend(
          cls("!bg-admin-error-fg hover:!bg-red-700"),
          dict.confirm,
          onClick --> { _ =>
            mode.set(Closed)
            events.emit(Deleted(app.id))
          }
        ),
      )
    )
  }
}
