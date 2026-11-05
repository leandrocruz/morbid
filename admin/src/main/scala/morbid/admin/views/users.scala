package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.ui.inputs.{InputType, InputVar, given}
import medulla.ui.modal.Modal
import medulla.ui.table.DataTable
import medulla.ui.{Buttons, Input}
import medulla.utils.Mediator
import morbid.admin.*
import morbid.admin.api.*
import morbid.admin.codec.given
import morbid.admin.converters.given
import morbid.domain.UserKind
import morbid.types.*
import org.scalajs.dom.window

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.util.{Failure, Success, Try}

object UsersView {

  sealed trait CrudEvent
  case class Created(item: UserResponse) extends CrudEvent
  case class Updated(item: UserResponse) extends CrudEvent
  case class Deleted(code: UserCode)     extends CrudEvent

  private sealed trait ModalMode
  private case object Closed                                      extends ModalMode
  private case object CreateMode                                  extends ModalMode
  private case class  EditMode    (user: UserResponse)            extends ModalMode
  private case class  DeleteMode  (user: UserResponse)            extends ModalMode
  private case class  PasswordMode(user: UserResponse)            extends ModalMode
  private case class  ResetMode   (user: UserResponse)            extends ModalMode
  private case class  PinMode     (user: UserResponse)            extends ModalMode

  private enum StatusFilter:
    case All, Active, Inactive

  private enum KindFilter:
    case All, Regular, Service

  private case class Filters(
    email  : String                 = "",
    status : StatusFilter           = StatusFilter.All,
    kind   : KindFilter             = KindFilter.All,
  ) {
    def isEmpty: Boolean = email.isEmpty && status == StatusFilter.All && kind == KindFilter.All
  }

  private def applyFilters(items: Seq[UserResponse], f: Filters): Seq[UserResponse] = {
    val q = f.email.trim.toLowerCase
    items
      .filter(u => q.isEmpty || Email.value(u.email).toLowerCase.contains(q))
      .filter(u => f.status match
        case StatusFilter.All      => true
        case StatusFilter.Active   => u.active
        case StatusFilter.Inactive => !u.active
      )
      .filter(u => f.kind match
        case KindFilter.All     => true
        case KindFilter.Regular => u.kind.forall(_ == UserKind.RE)
        case KindFilter.Service => u.kind.contains(UserKind.SA)
      )
  }

  def renderAll(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {
    div(
      PageHeader.render(dict.usersTitle, dict.usersSubtitle),
      div(
        cls("admin-card p-6 text-sm text-admin-muted"),
        p("Escolha uma conta na seção de contas para visualizar seus usuários.")
      )
    )
  }

  def renderForAccount(acc: AccountId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def columns(mode: Var[ModalMode]) = Seq(
      DataTable.Column[UserResponse](dict.columnEmail  , u => span(Email.value(u.email))),
      DataTable.Column[UserResponse](dict.columnCode   , u => span(cls("font-mono text-xs"), UserCode.value(u.code))),
      DataTable.Column[UserResponse](dict.columnStatus , u => StatusLabel.render(u.active)),
      DataTable.Column[UserResponse](dict.columnActions, u =>
        div(
          cls("flex items-center gap-2"),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("edit",         "text-lg"), onClick.mapTo(EditMode(u))     --> mode),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("lock_reset",   "text-lg"), onClick.mapTo(PasswordMode(u)) --> mode),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("mail",         "text-lg"), onClick.mapTo(ResetMode(u))    --> mode),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("pin",          "text-lg"), onClick.mapTo(PinMode(u))      --> mode),
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete",       "text-lg"), onClick.mapTo(DeleteMode(u))   --> mode),
        )
      ),
    )

    def applyChanges(tbl: DataTable.Table[UserId, UserResponse])(changes: Seq[CrudEvent], items: Seq[UserResponse]): Seq[UserResponse] = {
      changes.foldLeft(items) { (buffer, change) =>
        change match
          case Deleted(code) => buffer.filterNot(_.code == code)
          case Created(item) => buffer :+ item
          case Updated(item) =>
            tbl.row(item.id).foreach { row =>
              row.highlight(true)
              js.timers.setTimeout(1500)(row.highlight(false))
            }
            buffer.filterNot(_.id == item.id) :+ item
      }
    }

    val data    = Var(Option.empty[Try[Seq[UserResponse]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val filters = Var(Filters())
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val all     = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(tbl)(chs, items).sortBy(u => Email.value(u.email))
      case _                           => Seq.empty[UserResponse]
    }
    val rows    = all.combineWith(filters.signal).map((items, f) => applyFilters(items, f))

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
      case Closed             => div()
      case CreateMode         => renderCreateModal(acc, mode, events)
      case EditMode(u)        => renderEditModal(acc, u, mode, events)
      case DeleteMode(u)      => renderDeleteModal(acc, u, mode, events)
      case PasswordMode(u)    => renderPasswordModal(u, mode)
      case ResetMode(u)       => renderResetModal(u, mode)
      case PinMode(u)         => renderPinModal(u, mode)
    }

    def renderFilters = {
      val emailInput = input(
        cls("w-64 rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-admin-primary"),
        typ("text"),
        placeholder(dict.filterByEmail),
        controlled(
          value <-- filters.signal.map(_.email),
          onInput.mapToValue --> { v => filters.update(_.copy(email = v)) },
        ),
      )

      val statusSelect = select(
        cls("rounded border border-gray-300 px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-admin-primary"),
        value <-- filters.signal.map(_.status.toString),
        onChange.mapToValue --> { v =>
          val s = StatusFilter.values.find(_.toString == v).getOrElse(StatusFilter.All)
          filters.update(_.copy(status = s))
        },
        option(value(StatusFilter.All.toString)     , dict.filterStatusAll),
        option(value(StatusFilter.Active.toString)  , dict.filterStatusActive),
        option(value(StatusFilter.Inactive.toString), dict.filterStatusInactive),
      )

      val kindSelect = select(
        cls("rounded border border-gray-300 px-3 py-2 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-admin-primary"),
        value <-- filters.signal.map(_.kind.toString),
        onChange.mapToValue --> { v =>
          val k = KindFilter.values.find(_.toString == v).getOrElse(KindFilter.All)
          filters.update(_.copy(kind = k))
        },
        option(value(KindFilter.All.toString)    , dict.filterKindAll),
        option(value(KindFilter.Regular.toString), dict.filterKindRegular),
        option(value(KindFilter.Service.toString), dict.filterKindService),
      )

      val clearButton = Buttons.secondary.amend(
        dict.filterClear,
        disabled <-- filters.signal.map(_.isEmpty),
        onClick --> { _ => filters.set(Filters()) },
      )

      div(
        cls("admin-card !p-4 mb-4 flex flex-wrap items-center gap-3"),
        emailInput,
        statusSelect,
        kindSelect,
        clearButton,
      )
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      val empty  = rows.map(_.isEmpty).combineWith(filters.signal).map((isEmpty, f) => isEmpty && !f.isEmpty)
      val totals = rows.map(items => (items.count(_.active), items.count(u => !u.active)))
      div(
        renderFilters,
        StatusSummary.render(totals),
        div(cls("admin-card"), tbl.render(rows)),
        child.maybe <-- empty.map(e => Option.when(e)(
          div(cls("text-sm text-admin-muted text-center py-6"), dict.filterNoUsers)
        )),
      )
    }

    div(
      fetcher.execute(Endpoints.listUsers(acc)).map(Some(_)) --> data,
      PageHeader.render(dict.usersTitle, dict.usersSubtitle, Buttons.primary.amend(dict.usersNew, onClick.mapTo(CreateMode) --> mode)),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def modalFrame(title: String, mode: Var[ModalMode])(content: HtmlElement)(using dict: Dictionary): HtmlElement =
    div(
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), title),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      content
    )

  private def renderCreateModal(
    acc    : AccountId,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val email = InputVar.of[Email](Email.of(""))

    val req = email.must.map {
      case Failure(_)    => Failure(Exception(dict.usersEmailRequired))
      case Success(theEmail) =>
        if Email.value(theEmail).isBlank then Failure(Exception(dict.usersEmailRequired))
        else Success(CreateUserBody(theEmail, None, active = true))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.createUser(acc, r)))

    modalFrame(dict.usersNew, mode)(
      div(
        cls("contents"),
        med.wire,
        med.onlySuccesses.map(Created(_)) --> events,
        med.onlySuccesses.mapTo(Closed) --> mode,
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnEmail), Input.basic(email)),
        ),
        child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
          Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
        )
      )
    )
  }

  private def renderEditModal(
    acc    : AccountId,
    user   : UserResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val email  = InputVar.of[Email](user.email)
    val active = InputVar.of[Boolean](user.active)

    val req = InputVar.combine(Failure(Exception("")))(email.must, active.must) { (theEmail, isActive) =>
      if Email.value(theEmail).isBlank then Failure(Exception(dict.usersEmailRequired))
      else Success(UpdateUserBody(theEmail, isActive))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.updateUser(acc, user.code, r)))

    modalFrame(dict.edit, mode)(
      div(
        cls("contents"),
        med.wire,
        med.onlySuccesses.map(Updated(_)) --> events,
        med.onlySuccesses.mapTo(Closed) --> mode,
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(
            label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode),
            div(cls("font-mono text-sm text-admin-muted bg-gray-50 rounded px-3 py-2"), UserCode.value(user.code))
          ),
          div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnEmail), Input.basic(email)),
          div(cls("flex items-center gap-3"), Input.checkbox(active), label(cls("text-sm text-admin-text"), dict.active)),
        ),
        child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
          Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
        )
      )
    )
  }

  private def renderDeleteModal(
    acc    : AccountId,
    user   : UserResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val result  = trigger.events.flatMapSwitch { _ => fetcher.execute(Endpoints.deleteUser(acc, user.code)) }
    val busy    = Var(false)

    modalFrame(dict.deleteTitle, mode)(
      div(
        cls("contents"),
        trigger.events.mapTo(true) --> busy,
        result --> { r =>
          busy.set(false)
          r match
            case Success(_) => events.emit(Deleted(user.code)); mode.set(Closed)
            case Failure(_) => ()
        },
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(
            cls("flex items-center gap-3 p-4 bg-red-50 rounded-lg"),
            MaterialIcon("warning", "text-admin-error-fg text-2xl"),
            p(cls("text-sm text-admin-text"), dict.deleteMessage(Email.value(user.email)))
          ),
        ),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.cancel, disabled <-- busy.signal, onClick.mapTo(Closed) --> mode),
          Buttons.primary.amend(cls("!bg-admin-error-fg hover:!bg-red-700"), dict.confirm, disabled <-- busy.signal, onClick.mapToUnit --> trigger),
        )
      )
    )
  }

  private def renderPasswordModal(
    user : UserResponse,
    mode : Var[ModalMode],
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val password = InputVar.of[Password](Password.of(""))

    val req = password.must.map {
      case Failure(_)   => Failure(Exception(dict.passwordRequired))
      case Success(pwd) =>
        val raw = Password.value(pwd)
        if raw.length < 6 then Failure(Exception(dict.passwordMinLength))
        else Success(ChangePasswordBody(user.email, pwd))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.changePassword(r)))

    modalFrame(dict.passwordTitle, mode)(
      div(
        cls("contents"),
        med.wire,
        med.onlySuccesses.mapTo(Closed) --> mode,
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(cls("text-sm text-admin-muted"), s"${dict.columnEmail}: ${Email.value(user.email)}"),
          div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnPassword), Input.basic(password, kind = Signal.fromValue(InputType.password))),
        ),
        child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
          Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
        )
      )
    )
  }

  private def renderResetModal(
    user : UserResponse,
    mode : Var[ModalMode],
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val link    = Var(Option.empty[Try[PasswordResetResponse]])
    val busy    = Var(false)

    val stream = trigger.events.flatMapSwitch { _ =>
      fetcher.execute(Endpoints.resetPassword(PasswordResetBody(user.email)))
    }

    modalFrame(dict.passwordResetTitle, mode)(
      div(
        cls("contents"),
        trigger.events.mapTo(true) --> busy,
        stream --> { r =>
          busy.set(false)
          link.set(Some(r))
        },
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(cls("text-sm text-admin-muted"), s"${dict.columnEmail}: ${Email.value(user.email)}"),
          child <-- link.signal.map {
            case None                  => p(cls("text-sm"), dict.passwordResetMessage)
            case Some(Failure(err))    => p(cls("text-sm text-admin-error-fg"), err.getMessage)
            case Some(Success(result)) =>
              val linkText = morbid.types.Link.value(result.link)
              div(
                cls("flex flex-col gap-2"),
                p(cls("text-sm"), dict.passwordResetInfo),
                div(cls("font-mono text-xs break-all p-3 bg-gray-50 rounded border"), linkText),
                Buttons.secondary.amend(dict.copyLink, onClick.mapToUnit --> { _ => window.navigator.clipboard.writeText(linkText) })
              )
          }
        ),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.close, disabled <-- busy.signal, onClick.mapTo(Closed) --> mode),
          child <-- link.signal.map {
            case None => Buttons.primary.amend(dict.confirm, disabled <-- busy.signal, onClick.mapToUnit --> trigger)
            case _    => span()
          }
        )
      )
    )
  }

  private def renderPinModal(
    user : UserResponse,
    mode : Var[ModalMode],
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val pin = InputVar.of[Pin](Pin.of(""))

    val req = pin.must.map {
      case Failure(_)      => Failure(Exception(dict.pinMinLength))
      case Success(thePin) =>
        val raw = Pin.value(thePin)
        if raw.length < 4 then Failure(Exception(dict.pinMinLength))
        else Success(SetPinBody(user.email, thePin))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.setPin(r)))

    modalFrame(dict.pinTitle, mode)(
      div(
        cls("contents"),
        med.wire,
        med.onlySuccesses.mapTo(Closed) --> mode,
        div(
          cls("flex flex-col gap-4 p-6 flex-1"),
          div(cls("text-sm text-admin-muted"), s"${dict.columnEmail}: ${Email.value(user.email)}"),
          div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnPin), Input.basic(pin)),
        ),
        child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
        div(
          cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
          Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
          Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
        )
      )
    )
  }
}
