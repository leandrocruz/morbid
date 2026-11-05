package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.table.DataTable
import medulla.ui.{Buttons, Input}
import medulla.utils.{Mediator, Signals}
import morbid.admin.*
import morbid.admin.api.*
import morbid.admin.codec.given
import morbid.admin.converters.given
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.util.{Failure, Success, Try}

object AccountsView {

  sealed trait CrudEvent
  case class Created(item: AccountResponse) extends CrudEvent
  case class Updated(item: AccountResponse) extends CrudEvent
  case class Deleted(id: AccountId)         extends CrudEvent

  private sealed trait ModalMode
  private case object Closed     extends ModalMode
  private case object CreateMode extends ModalMode
  private case class EditMode  (acc: AccountResponse) extends ModalMode
  private case class DeleteMode(acc: AccountResponse) extends ModalMode

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def columns(mode: Var[ModalMode]) = Seq(
      DataTable.Column[AccountResponse](dict.columnName   , it => span(AccountName.value(it.name))),
      DataTable.Column[AccountResponse](dict.columnCode   , it => span(cls("font-mono text-xs"), AccountCode.value(it.code))),
      DataTable.Column[AccountResponse](dict.columnId     , it => span(AccountId.value(it.id))),
      DataTable.Column[AccountResponse](dict.columnStatus , it => StatusLabel.render(it.active)),
      DataTable.Column[AccountResponse](dict.columnActions, it =>
        div(
          cls("flex items-center gap-2"),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("edit",   "text-lg"), onClick.mapTo(EditMode(it))   --> mode),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode),
        )
      ),
    )

    def applyChanges(tbl: DataTable.Table[AccountId, AccountResponse])(changes: Seq[CrudEvent], items: Seq[AccountResponse]): Seq[AccountResponse] = {
      changes.foldLeft(items) { (buffer, change) =>
        change match
          case Deleted(id)   => buffer.filterNot(_.id == id)
          case Created(item) => buffer :+ item
          case Updated(item) =>
            tbl.row(item.id).foreach { row =>
              row.highlight(true)
              js.timers.setTimeout(1500)(row.highlight(false))
            }
            buffer.filterNot(_.id == item.id) :+ item
      }
    }

    val data    = Var(Option.empty[Try[Seq[AccountResponse]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val rows    = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(tbl)(chs, items).sortBy(a => AccountName.value(a.name))
      case _                           => Seq.empty[AccountResponse]
    }

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
      case CreateMode      => renderCreateModal(mode, events)
      case EditMode(acc)   => renderEditModal  (acc, mode, events)
      case DeleteMode(acc) => renderDeleteModal(acc, mode, events)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    div(
      fetcher.execute(Endpoints.listAccounts).map(Some(_)) --> data,
      PageHeader.render(dict.accountsTitle, dict.accountsSubtitle, Buttons.primary.amend(dict.accountsNew, onClick.mapTo(CreateMode) --> mode)),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def renderCreateModal(
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val name   = InputVar.of[AccountName](AccountName.of(""))
    val code   = InputVar.of[AccountCode](AccountCode.of(""))
    val tenant = InputVar.of[String]("1")

    val req = InputVar.combine(Failure(Exception("")))(name.must, code.must, tenant.must) { (theName, theCode, theTenantStr) =>
      (AccountName.value(theName).isBlank, AccountCode.value(theCode).isBlank, Try(theTenantStr.toLong)) match
        case (true, _, _)              => Failure(Exception(dict.accountsNameRequired))
        case (_, true, _)              => Failure(Exception(dict.accountsCodeRequired))
        case (_, _, Failure(_))        => Failure(Exception(dict.accountsTenantRequired))
        case (_, _, Success(tenantId)) => Success(CreateAccountBody(TenantId.of(tenantId), theCode, theName, active = true))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.createAccount(r)))

    div(
      med.wire,
      med.onlySuccesses.map(Created(_)) --> events,
      med.onlySuccesses.mapTo(Closed) --> mode,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.accountsNew),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName), Input.basic(name)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode), Input.basic(code)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnTenant), Input.basic(tenant)),
      ),
      child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), s"${err.getMessage}")),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
        Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
      )
    )
  }

  private def renderEditModal(
    acc    : AccountResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val name   = InputVar.of[AccountName](acc.name)
    val active = InputVar.of[Boolean](acc.active)

    val req = InputVar.combine(Failure(Exception("")))(name.must, active.must) { (theName, isActive) =>
      if AccountName.value(theName).isBlank then Failure(Exception(dict.accountsNameRequired))
      else Success(UpdateAccountBody(theName, isActive))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.updateAccount(acc.id, r)))

    div(
      med.wire,
      med.onlySuccesses.map(Updated(_)) --> events,
      med.onlySuccesses.mapTo(Closed) --> mode,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.edit),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode),
          div(cls("font-mono text-sm text-admin-muted bg-gray-50 rounded px-3 py-2"), AccountCode.value(acc.code))
        ),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName), Input.basic(name)),
        div(
          cls("flex items-center gap-3"),
          Input.checkbox(active),
          label(cls("text-sm text-admin-text"), dict.active)
        ),
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
    acc    : AccountResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val result  = trigger.events.flatMapSwitch { _ => fetcher.execute(Endpoints.deleteAccount(acc.id)) }
    val busy    = Var(false)

    div(
      trigger.events.mapTo(true) --> busy,
      result --> { r =>
        busy.set(false)
        r match
          case Success(_)   => events.emit(Deleted(acc.id)); mode.set(Closed)
          case Failure(_)   => ()
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
          p(cls("text-sm text-admin-text"), dict.deleteMessage(AccountName.value(acc.name)))
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
