package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.{Buttons, Input}
import medulla.utils.{Mediator, Signals}
import morbid.admin.*
import morbid.domain.raw.RawApplicationDetails
import morbid.protocol.{AllApplications, UpdateApplicationRequest}
import morbid.types.*
import morbid.converters.given
import org.scalajs.dom.console

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object ApplicationsView {

  private sealed trait ModalMode
  private case class EditMode  (app: RawApplicationDetails) extends ModalMode
  private case class DeleteMode(app: RawApplicationDetails) extends ModalMode

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val apps        = Var(Option.empty[Try[Seq[RawApplicationDetails]]])
    val filter      = Var("")
    val modalMode   = Var(Option.empty[ModalMode])
    val modalOpened = Var(false)

    def openEdit(app: RawApplicationDetails): Unit = {
      modalMode.set(Some(EditMode(app)))
      modalOpened.set(true)
    }

    def openDelete(app: RawApplicationDetails): Unit = {
      modalMode.set(Some(DeleteMode(app)))
      modalOpened.set(true)
    }

    val columns = Seq(
      DataTable.Column[RawApplicationDetails](dict.columnName    , it => span(ApplicationName.value(it.name))),
      DataTable.Column[RawApplicationDetails](dict.columnCode    , it => span(cls("font-mono text-xs"), ApplicationCode.value(it.code))),
      DataTable.Column[RawApplicationDetails](dict.columnStatus  , it => StatusLabel.render(it.active)),
      DataTable.Column[RawApplicationDetails](dict.columnGroups  , it => Pills.of(Seq(a(dict.groups, AdminRouter.instance.linkTo(GroupsPage(it.id)))))),
      DataTable.Column[RawApplicationDetails](dict.columnActions , it =>
        div(
          cls("flex items-center gap-2"),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text"),     MaterialIcon("edit", "text-lg"),   onClick --> { _ => openEdit  (it) }),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick --> { _ => openDelete(it) }),
        )
      ),
    )

    val results = Signals.and(apps, filter) {
      case (None                , _       ) => div(dict.loading)
      case (Some(Failure(err))  , _       ) => div(s"Load Error: ${err.getMessage}")
      case (Some(Success(items)), filterBy) =>
        val filtered = items.filter(it => ApplicationName.value(it.name).toLowerCase.contains(filterBy.toLowerCase))
        DataTable.render(filtered, columns)
    }

    val modalContent = modalMode.signal.map {
      case None                  => div()
      case Some(EditMode(app))   => renderEditModal  (app, modalOpened)
      case Some(DeleteMode(app)) => renderDeleteModal(app, modalOpened)
    }

    div(
      fetcher.execute(Endpoints.applications(AllApplications())).map(Some(_)) --> apps,
      PageHeader.render(dict.appsTitle, dict.appsSubtitle),
      child <-- results,
      child.maybe <-- Modal(modalOpened, modalContent),
    )
  }

  private def renderEditModal(app: RawApplicationDetails, opened: Var[Boolean])(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val name   = InputVar.of[ApplicationName](app.name)
    val active = InputVar.of[Boolean](app.active)

    val req: Signal[Try[UpdateApplicationRequest]] = InputVar.combine(Failure(Exception("ERRO")))(name.must, active.must) {
      (n: ApplicationName, a: Boolean) =>
        ApplicationName.value(n) match {
          case "xxx" => Failure(Exception("BAD NAME"))
          case _     => Success(UpdateApplicationRequest(app.id, a, n))
        }
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.applicationUpdate(r)))

    div(
      med.wire,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.edit),
        button(
          cls("text-admin-muted hover:text-admin-text"),
          MaterialIcon("close"),
          onClick.mapTo(false) --> opened
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
        Buttons.secondary.amend(dict.cancel, onClick.mapTo(false) --> opened),
        Buttons.primary.amend(
          dict.save,
          disabled <-- med.disabled,
          onClick.mapToUnit --> med.trigger
        ),
      )
    )
  }

  private def renderDeleteModal(app: RawApplicationDetails, opened: Var[Boolean])(using dict: Dictionary): HtmlElement = {
    div(
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-error-fg"), dict.deleteTitle),
        button(
          cls("text-admin-muted hover:text-admin-text"),
          MaterialIcon("close"),
          onClick.mapTo(false) --> opened
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
        Buttons.secondary.amend(dict.cancel, onClick.mapTo(false) --> opened),
        Buttons.primary.amend(
          cls("!bg-admin-error-fg hover:!bg-red-700"),
          dict.confirm,
          onClick --> { _ =>
            // TODO: call delete endpoint
            opened.set(false)
          }
        ),
      )
    )
  }
}
