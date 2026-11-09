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
import org.scalajs.dom

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object ApiKeysView {

  sealed trait CrudEvent
  case class Issued(item: ApiKeyResponse)  extends CrudEvent
  case class Revoked(code: UserCode)       extends CrudEvent

  private sealed trait ModalMode
  private case object Closed                              extends ModalMode
  private case object CreateMode                          extends ModalMode
  private case class  IssuedMode(result: ApiKeyIssuedResponse)  extends ModalMode
  private case class  DeleteMode(item: ApiKeyResponse)    extends ModalMode

  def render(acc: AccountId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def actionBtns(mode: Var[ModalMode], it: ApiKeyResponse) = {
      val admin = Session.isAdmin
      div(
        cls("flex items-center gap-2"),
        child.maybe <-- admin.map(Option.when(_)(
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode)
        )),
      )
    }

    def columns(mode: Var[ModalMode]) = Seq(
      DataTable.Column[ApiKeyResponse](dict.columnEmail  , it => span(Email.value(it.email))),
      DataTable.Column[ApiKeyResponse](dict.columnCode   , it => span(cls("font-mono text-xs"), UserCode.value(it.code))),
      DataTable.Column[ApiKeyResponse](dict.columnStatus , it => StatusLabel.render(it.active)),
      DataTable.Column[ApiKeyResponse](dict.columnActions, it => actionBtns(mode, it)),
    )

    def applyChanges(changes: Seq[CrudEvent], items: Seq[ApiKeyResponse]): Seq[ApiKeyResponse] =
      changes.foldLeft(items) { (buf, ev) =>
        ev match
          case Issued(it)    => buf :+ it
          case Revoked(code) => buf.filterNot(_.code == code)
      }

    val data    = Var(Option.empty[Try[Seq[ApiKeyResponse]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val rows    = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(chs, items).sortBy(k => Email.value(k.email))
      case _                           => Seq.empty[ApiKeyResponse]
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
      case CreateMode      => renderCreateModal(acc, mode, events)
      case IssuedMode(r)   => renderIssuedModal(r, mode)
      case DeleteMode(it)  => renderDeleteModal(acc, it, mode, events)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    val headerAction = div(
      child.maybe <-- Session.isAdmin.map(Option.when(_)(
        Buttons.primary.amend(dict.apiKeysNew, onClick.mapTo(CreateMode) --> mode)
      ))
    )

    div(
      fetcher.execute(Endpoints.listApiKeys(acc)).map(Some(_)) --> data,
      PageHeader.render(dict.apiKeysTitle, s"${dict.apiKeysSubtitle} (acc #${AccountId.value(acc)})", headerAction),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def renderCreateModal(
    acc    : AccountId,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val email = InputVar.of[Email](Email.of(""))
    val days  = Var("")

    val req = email.must.combineWith(days.signal).map { (emailTry, daysStr) =>
      emailTry.flatMap { theEmail =>
        if Email.value(theEmail).isBlank then Failure(Exception(dict.usersEmailRequired))
        else
          val maybeDays = daysStr.trim match
            case "" => None
            case s  => s.toIntOption
          Success(CreateApiKeyBody(email = theEmail, name = None, days = maybeDays))
      }
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.issueApiKey(acc, r)))

    div(
      med.wire,
      med.onlySuccesses --> { r =>
        events.emit(Issued(r.user))
        mode.set(IssuedMode(r))
      },
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.apiKeysNew),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnEmail), Input.basic(email)),
        div(
          label(cls("block text-sm font-medium text-admin-text mb-1"), dict.apiKeysDays),
          input(
            cls("medulla"),
            typ("number"),
            placeholder("365"),
            controlled(value <-- days.signal, onInput.mapToValue --> days)
          ),
          p(cls("text-xs text-admin-muted mt-1"), dict.apiKeysDaysHint),
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

  private def renderIssuedModal(
    result : ApiKeyIssuedResponse,
    mode   : Var[ModalMode],
  )(using dict: Dictionary): HtmlElement = {

    def copy() = {
      val navClipboard = dom.window.navigator.clipboard
      if navClipboard != null then navClipboard.writeText(result.token)
    }

    div(
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.apiKeysIssued),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          cls("flex items-center gap-3 p-4 bg-yellow-50 rounded-lg"),
          MaterialIcon("warning", "text-amber-600 text-2xl"),
          p(cls("text-sm text-admin-text"), dict.apiKeysIssuedHint)
        ),
        div(
          cls("font-mono text-xs break-all bg-gray-50 border border-gray-200 rounded p-3"),
          result.token
        ),
      ),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.apiKeysCopyToken, onClick --> { _ => copy() }),
        Buttons.primary.amend(dict.close, onClick.mapTo(Closed) --> mode),
      )
    )
  }

  private def renderDeleteModal(
    acc    : AccountId,
    item   : ApiKeyResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val result  = trigger.events.flatMapSwitch { _ => fetcher.execute(Endpoints.deleteApiKey(acc, item.code)) }
    val busy    = Var(false)

    div(
      trigger.events.mapTo(true) --> busy,
      result --> { r =>
        busy.set(false)
        r match
          case Success(_) => events.emit(Revoked(item.code)); mode.set(Closed)
          case Failure(_) => ()
      },
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-error-fg"), dict.apiKeysRevoke),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(
          cls("flex items-center gap-3 p-4 bg-red-50 rounded-lg"),
          MaterialIcon("warning", "text-admin-error-fg text-2xl"),
          p(cls("text-sm text-admin-text"), dict.deleteMessage(Email.value(item.email)))
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
