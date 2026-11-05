package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.table.DataTable
import medulla.ui.{Buttons, Input}
import medulla.utils.Mediator
import morbid.admin.*
import morbid.admin.api.*
import morbid.admin.codec.given
import morbid.admin.converters.given
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object GroupsView {

  sealed trait CrudEvent
  case class Created(item: GroupResponse) extends CrudEvent
  case class Deleted(code: GroupCode)     extends CrudEvent

  private sealed trait ModalMode
  private case object Closed                            extends ModalMode
  private case object CreateMode                        extends ModalMode
  private case class DeleteMode(group: GroupResponse)   extends ModalMode

  def render(app: ApplicationCode)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def columns(mode: Var[ModalMode]) = Seq(
      DataTable.Column[GroupResponse](dict.columnName   , it => span(GroupName.value(it.name))),
      DataTable.Column[GroupResponse](dict.columnCode   , it => span(cls("font-mono text-xs"), GroupCode.value(it.code))),
      DataTable.Column[GroupResponse](dict.columnRoles  , it => Pills.of(it.roles.map(r => RoleCode.value(r)))),
      DataTable.Column[GroupResponse](dict.columnActions, it =>
        div(
          cls("flex items-center gap-2"),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode),
        )
      ),
    )

    def applyChanges(changes: Seq[CrudEvent], items: Seq[GroupResponse]): Seq[GroupResponse] =
      changes.foldLeft(items) { (buffer, change) =>
        change match
          case Deleted(code) => buffer.filterNot(_.code == code)
          case Created(item) => buffer :+ item
      }

    val data    = Var(Option.empty[Try[Seq[GroupResponse]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val rows    = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(chs, items).sortBy(g => GroupName.value(g.name))
      case _                           => Seq.empty[GroupResponse]
    }

    val opened = mode.signal.map {
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
      case CreateMode      => renderCreateModal(app, mode, events)
      case DeleteMode(g)   => renderDeleteModal(app, g, mode, events)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    div(
      fetcher.execute(Endpoints.listGroups(app)).map(Some(_)) --> data,
      PageHeader.render(dict.groupsTitle, s"${dict.groupsSubtitle} (${ApplicationCode.value(app)})", Buttons.primary.amend(dict.groupsNew, onClick.mapTo(CreateMode) --> mode)),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def renderCreateModal(
    app    : ApplicationCode,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val code = InputVar.of[GroupCode](GroupCode.of(""))
    val name = InputVar.of[GroupName](GroupName.of(""))

    val req = InputVar.combine(Failure(Exception("")))(name.must, code.must) { (theName, theCode) =>
      if GroupName.value(theName).isBlank then Failure(Exception(dict.groupsNameRequired))
      else
        val codeOpt = if GroupCode.value(theCode).isBlank then None else Some(theCode)
        Success(CreateGroupBody(code = codeOpt, name = theName))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.createGroup(app, r)))

    div(
      med.wire,
      med.onlySuccesses.map(Created(_)) --> events,
      med.onlySuccesses.mapTo(Closed) --> mode,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.groupsNew),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName), Input.basic(name)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode + " (opcional)"), Input.basic(code)),
      ),
      child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
        Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
      )
    )
  }

  private def renderDeleteModal(
    app    : ApplicationCode,
    group  : GroupResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val result  = trigger.events.flatMapSwitch { _ => fetcher.execute(Endpoints.deleteGroup(app, group.code)) }
    val busy    = Var(false)

    div(
      trigger.events.mapTo(true) --> busy,
      result --> { r =>
        busy.set(false)
        r match
          case Success(_) => events.emit(Deleted(group.code)); mode.set(Closed)
          case Failure(_) => ()
      },
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-error-fg"), dict.deleteTitle),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          cls("flex items-center gap-3 p-4 bg-red-50 rounded-lg"),
          MaterialIcon("warning", "text-admin-error-fg text-2xl"),
          p(cls("text-sm text-admin-text"), dict.deleteMessage(GroupName.value(group.name)))
        ),
      ),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.cancel, disabled <-- busy.signal, onClick.mapTo(Closed) --> mode),
        Buttons.primary.amend(cls("!bg-admin-error-fg hover:!bg-red-700"), dict.confirm, disabled <-- busy.signal, onClick.mapToUnit --> trigger),
      )
    )
  }
}

object RolesListView {

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {
    val PrestoApp = ApplicationCode.of("presto")

    val columns = Seq(
      DataTable.Column[RoleResponse](dict.columnName, r => span(RoleName.value(r.name))),
      DataTable.Column[RoleResponse](dict.columnCode, r => span(cls("font-mono text-xs"), RoleCode.value(r.code))),
      DataTable.Column[RoleResponse](dict.columnId  , r => span(RoleId.value(r.id))),
    )

    val data = Var(Option.empty[Try[Seq[RoleResponse]]])

    val content = data.signal.map {
      case None                  => div(dict.loading)
      case Some(Failure(err))    => div(s"Load Error: ${err.getMessage}")
      case Some(Success(result)) => DataTable.simple(columns, _.id).render(Signal.fromValue(result.sortBy(r => RoleName.value(r.name))))
    }

    div(
      fetcher.execute(Endpoints.listRoles(PrestoApp)).map(Some(_)) --> data,
      PageHeader.render(s"${dict.sidebarRoles}", s"Roles of ${ApplicationCode.value(PrestoApp)}"),
      div(cls("admin-card"), child <-- content)
    )
  }
}

object DashboardView {

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {
    div(
      PageHeader.render("Morbid Admin", "Administração centralizada de contas, usuários, grupos e aplicações"),
      div(
        cls("grid grid-cols-1 md:grid-cols-3 gap-4"),
        statCard(dict.sidebarAccounts   , "apartment"),
        statCard(dict.sidebarApps       , "apps"),
        statCard(dict.sidebarRoles      , "admin_panel_settings"),
      )
    )
  }

  private def statCard(label: String, icon: String): HtmlElement =
    div(
      cls("admin-card p-6 flex items-center gap-4"),
      MaterialIcon(icon, "text-admin-accent text-3xl"),
      span(cls("text-lg font-medium text-admin-text"), label)
    )
}
