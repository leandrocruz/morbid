package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.{Buttons, Input}
import medulla.utils.{Mediator, Signals}
import morbid.admin.*
import morbid.converters.given
import morbid.domain.raw.RawApplicationDetails
import morbid.protocol.{AllApplications, UpdateApplicationRequest}
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}
import scala.scalajs.js.timers.setTimeout

object ApplicationsView {

  type States = (Option[Try[Seq[RawApplicationDetails]]], Option[String], Option[CrudEvent])

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

    def renderTable(items: Seq[RawApplicationDetails], filter: Option[String], event: Option[CrudEvent], mode: Var[ModalMode]) = {

      def highlight(flag: Signal[Boolean])(app: RawApplicationDetails): Signal[Boolean] = {
        event match
          case None                => Signals.and(flag, Signal.fromValue(false)) { _ && _ }
          case Some(Deleted(_))    => Signals.and(flag, Signal.fromValue(false)) { _ && _ }
          case Some(Created(item)) => Signals.and(flag, Signal.fromValue(app.id == item.id)) { _ && _ }
          case Some(Updated(item)) => Signals.and(flag, Signal.fromValue(app.id == item.id)) { _ && _ }
      }

      val flag = Var[Boolean](true)
      DataTable
        .render(items.sortBy(_.name), columns(mode), highlight(flag.signal))
        .amend(
          EventStream.delay(2500).mapTo(false) --> flag //clears the highlight
        )
    }

    def updateItems(items: Option[Try[Seq[RawApplicationDetails]]], event: Option[CrudEvent]): Option[Try[Seq[RawApplicationDetails]]] = {

      def update(seq: Seq[RawApplicationDetails])(evt: CrudEvent): Seq[RawApplicationDetails] = {
        evt match
          case Created(item) => seq :+ item
          case Updated(item) => seq.filterNot(_.id == item.id) :+ item
          case Deleted(id)   => seq.filterNot(_.id == id)
      }

      items.map(_.map(seq => event.map(update(seq)).getOrElse(seq)))
    }

    val loaded  = Var(Option.empty[Try[Seq[RawApplicationDetails]]])
    val filter  = Var(Option.empty[String])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val event   = Var(Option.empty[CrudEvent])
    val updates = loaded.signal.combineWith(event).map(updateItems).distinct
    val states  = updates.signal.combineWith(filter).combineWith(event)
    val opened  = mode.signal.map {
      case Closed => false
      case _      => true
    }

    val results = states.map {
      case (None                , _       , _  ) => div(dict.loading)
      case (Some(Failure(err))  , _       , _  ) => div(s"Load Error: ${err.getMessage}")
      case (Some(Success(items)), filterBy, evt) => renderTable(items, filterBy, evt, mode)
    }

    val modalContent = mode.signal.map {
      case Closed          => div()
      case EditMode(app)   => renderEditModal  (app, mode, event)
      case DeleteMode(app) => renderDeleteModal(app, mode, event)
    }

    div(
      fetcher.execute(Endpoints.applications(AllApplications())).map(Some(_)) --> loaded,
      updates --> loaded,
      PageHeader.render(dict.appsTitle, dict.appsSubtitle),
      child       <-- results,
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def renderEditModal(
    app   : RawApplicationDetails,
    mode  : Var[ModalMode],
    event : Var[Option[CrudEvent]]
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
      med.successes.map(_.map(Updated(_))) --> event, //fires when the item is updated
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
    app   : RawApplicationDetails,
    mode  : Var[ModalMode],
    event : Var[Option[CrudEvent]]
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
            event.set(Some(Deleted(app.id)))
          }
        ),
      )
    )
  }
}
