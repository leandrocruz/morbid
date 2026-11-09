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

  def render(acc: AccountId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    /** App whose groups are being viewed, within the account named in the URL.
      * Groups are per-(account, app), so picking the app happens on the page.
      * Defaults to the first app linked to the account, once that list loads. */
    val pickedApp: Var[Option[ApplicationCode]] = Var(None)

    val appsFlow = fetcher.execute(Endpoints.listAccountApps(acc))
    val apps     = Var(Option.empty[Try[Seq[ApplicationResponse]]])

    def columns(mode: Var[ModalMode], canWrite: Signal[Boolean]) = Seq(
      DataTable.Column[GroupResponse](dict.columnName   , it => span(GroupName.value(it.name))),
      DataTable.Column[GroupResponse](dict.columnCode   , it => span(cls("font-mono text-xs"), GroupCode.value(it.code))),
      DataTable.Column[GroupResponse](dict.columnRoles  , it => Pills.of(it.roles.map(r => RoleCode.value(r)))),
      DataTable.Column[GroupResponse](dict.usersTitle   , it =>
        span(
          child.maybe <-- pickedApp.signal.map(_.map { app =>
            a(
              cls("inline-flex items-center gap-1 text-admin-muted hover:text-admin-text cursor-pointer"),
              AdminRouter.instance.linkTo(GroupUsersPage(acc, app, it.code)),
              MaterialIcon("people", "text-lg"),
              span(cls("text-sm"), dict.usersTitle),
            )
          })
        )
      ),
      DataTable.Column[GroupResponse](dict.columnActions, it =>
        div(
          cls("flex items-center gap-2"),
          child.maybe <-- canWrite.map(Option.when(_)(
            button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode)
          )),
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

    /** Create/Delete are only enabled when viewing the signed-in admin's own
      * account AND they have the admin role on the selected app, because the
      * server-side storeGroup/removeGroup routes write in the caller's
      * account scope. Viewing another account's groups is read-only. */
    val isOwnAccount = Session.account.signal.map(_.contains(acc))
    val canWrite     = isOwnAccount.combineWith(pickedApp.signal).combineWith(Session.apps.signal).map {
      case (own, Some(code), appsList) => own && appsList.exists(a => a.code == code && a.isAdmin)
      case _                           => false
    }

    val tbl     = DataTable.simple(columns(mode, canWrite), _.id)
    val rows    = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(chs, items).sortBy(g => GroupName.value(g.name))
      case _                           => Seq.empty[GroupResponse]
    }

    val opened = mode.signal.map {
      case Closed => false
      case _      => true
    }

    val status = pickedApp.signal.combineWith(data.signal).map {
      case (None,    _)                       => (false, Some(div(cls("text-sm text-admin-muted"), dict.groupsNoApps)))
      case (_,       None)                    => (false, Some(div(dict.loading)))
      case (_,       Some(Failure(err)))      => (false, Some(div(s"Load Error: ${err.getMessage}")))
      case (_,       Some(Success(_)))        => (true , None)
    }

    /** For create/delete modals the app code must be present — gated by
      * `canWrite`, so this is only reached when `pickedApp` is defined. */
    val modalContent = mode.signal.combineWith(pickedApp.signal).map {
      case (Closed,          _)             => div()
      case (CreateMode,      Some(appCode)) => renderCreateModal(appCode, mode, events)
      case (DeleteMode(g),   Some(appCode)) => renderDeleteModal(appCode, g, mode, events)
      case _                                => div()
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    /** Re-fetch groups whenever the picked app changes. */
    val loadTrigger = EventBus[Option[ApplicationCode]]()
    val groupsFlow: EventStream[Option[Try[Seq[GroupResponse]]]] = loadTrigger.events.flatMapSwitch {
      case Some(code) => fetcher.execute(Endpoints.listGroups(code, Some(acc))).map(Some(_))
      case None       => EventStream.fromValue(Option.empty[Try[Seq[GroupResponse]]])
    }

    /** Auto-pick the first linked app when the apps list resolves. */
    val appsObserver: Observer[Option[Try[Seq[ApplicationResponse]]]] = Observer {
      case Some(Success(items)) if pickedApp.now().isEmpty =>
        items.sortBy(a => ApplicationName.value(a.name)).headOption.foreach(a => pickedApp.set(Some(a.code)))
      case _ => ()
    }

    def renderAppPicker(items: Seq[ApplicationResponse]): HtmlElement = {
      val Placeholder = "__none__"
      val selectedValue = pickedApp.signal.map {
        case Some(code) => ApplicationCode.value(code)
        case None       => Placeholder
      }
      select(
        cls("text-sm border border-admin-border rounded-sm px-2 py-1 bg-white"),
        option(value(Placeholder), dict.selectApp),
        items.sortBy(a => ApplicationName.value(a.name)).map { a =>
          option(value(ApplicationCode.value(a.code)), ApplicationName.value(a.name))
        },
        controlled(
          value <-- selectedValue,
          onChange.mapToValue --> { v =>
            if v == Placeholder then pickedApp.set(None)
            else                     pickedApp.set(Some(ApplicationCode.of(v)))
          }
        )
      )
    }

    val appPicker = apps.signal.map {
      case Some(Success(items)) if items.nonEmpty => renderAppPicker(items)
      case Some(Success(_))                       => span(cls("text-sm text-admin-muted"), dict.groupsNoApps)
      case _                                      => span(cls("text-sm text-admin-muted"), dict.loading)
    }

    div(
      appsFlow.map(Some(_)) --> apps,
      apps.signal --> appsObserver,
      pickedApp.signal --> loadTrigger.writer,
      groupsFlow --> data,
      PageHeader.render(dict.groupsTitle, s"${dict.groupsSubtitle} (acc #${AccountId.value(acc)})", div(
        cls("flex items-center gap-3"),
        child <-- appPicker,
        child.maybe <-- canWrite.map(Option.when(_)(
          Buttons.primary.amend(dict.groupsNew, onClick.mapTo(CreateMode) --> mode)
        ))
      )),
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

object GroupUsersView {

  def render(acc: AccountId, app: ApplicationCode, grp: GroupCode)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val columns = Seq(
      DataTable.Column[UserResponse](dict.columnEmail , u => span(Email.value(u.email))),
      DataTable.Column[UserResponse](dict.columnCode  , u => span(cls("font-mono text-xs"), UserCode.value(u.code))),
      DataTable.Column[UserResponse](dict.columnKind  , u => span(u.kind.map(_.toString).getOrElse("-"))),
      DataTable.Column[UserResponse](dict.columnStatus, u => StatusLabel.render(u.active)),
    )

    val data = Var(Option.empty[Try[Seq[UserResponse]]])

    val content = data.signal.map {
      case None                  => div(dict.loading)
      case Some(Failure(err))    => div(s"Load Error: ${err.getMessage}")
      case Some(Success(items))  => DataTable.simple(columns, _.id).render(Signal.fromValue(items.sortBy(u => Email.value(u.email))))
    }

    val subtitle = s"${GroupCode.value(grp)} @ ${ApplicationCode.value(app)} (acc #${AccountId.value(acc)})"

    div(
      fetcher.execute(Endpoints.listGroupUsers(acc, app, grp)).map(Some(_)) --> data,
      PageHeader.render(dict.groupUsersTitle, subtitle),
      div(cls("admin-card"), child <-- content),
    )
  }
}

object RolesListView {

  def render(app: ApplicationCode)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

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
      fetcher.execute(Endpoints.listRoles(app)).map(Some(_)) --> data,
      PageHeader.render(dict.sidebarRoles, s"${dict.rolesSubtitle} (${ApplicationCode.value(app)})"),
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
