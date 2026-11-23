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
import morbid.domain.ProviderKind
import morbid.types.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.util.{Failure, Success, Try}

object ProvidersView {

  sealed trait CrudEvent
  case class Created(item: ProviderResponse) extends CrudEvent
  case class Updated(item: ProviderResponse) extends CrudEvent
  case class Deleted(id: ProviderId)         extends CrudEvent

  private sealed trait ModalMode
  private case object Closed                               extends ModalMode
  private case object CreateMode                           extends ModalMode
  private case class  EditMode   (item: ProviderResponse)  extends ModalMode
  private case class  DeleteMode (item: ProviderResponse)  extends ModalMode

  private def kindLabel(kind: ProviderKind)(using dict: Dictionary): String = kind match
    case ProviderKind.UP   => dict.providersKindUP
    case ProviderKind.SAML => dict.providersKindSAML

  def render(acc: AccountId)(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    def actionBtns(mode: Var[ModalMode], it: ProviderResponse) = {
      val admin = Session.isAdmin
      div(
        cls("flex items-center gap-2"),
        child.maybe <-- admin.map(Option.when(_)(
          button(cls("cursor-pointer text-admin-muted hover:text-admin-text")    , MaterialIcon("edit",   "text-lg"), onClick.mapTo(EditMode(it))   --> mode)
        )),
        child.maybe <-- admin.map(Option.when(_)(
          button(cls("cursor-pointer text-admin-muted hover:text-admin-error-fg"), MaterialIcon("delete", "text-lg"), onClick.mapTo(DeleteMode(it)) --> mode)
        )),
      )
    }

    def columns(mode: Var[ModalMode]) = Seq(
      DataTable.Column[ProviderResponse](dict.columnName          , it => span(ProviderName.value(it.name))),
      DataTable.Column[ProviderResponse](dict.columnCode          , it => span(cls("font-mono text-xs"), ProviderCode.value(it.code))),
      DataTable.Column[ProviderResponse](dict.providersDomain     , it => span(Domain.value(it.domain))),
      DataTable.Column[ProviderResponse](dict.providersKind       , it => span(kindLabel(it.kind))),
      DataTable.Column[ProviderResponse](dict.columnStatus        , it => StatusLabel.render(it.active)),
      DataTable.Column[ProviderResponse](dict.columnActions       , it => actionBtns(mode, it)),
    )

    def applyChanges(tbl: DataTable.Table[ProviderId, ProviderResponse])(changes: Seq[CrudEvent], items: Seq[ProviderResponse]): Seq[ProviderResponse] =
      changes.foldLeft(items) { (buf, ev) =>
        ev match
          case Created(it) => buf :+ it
          case Updated(it) =>
            tbl.row(it.id).foreach { row =>
              row.highlight(true)
              js.timers.setTimeout(1500)(row.highlight(false))
            }
            buf.filterNot(_.id == it.id) :+ it
          case Deleted(id) => buf.filterNot(_.id == id)
      }

    val data    = Var(Option.empty[Try[Seq[ProviderResponse]]])
    val mode    = Var(Closed.asInstanceOf[ModalMode])
    val events  = EventBus[CrudEvent]()
    val changes = events.events.scanLeft(Seq.empty[CrudEvent])(_ :+ _)
    val tbl     = DataTable.simple(columns(mode), _.id)
    val rows    = changes.combineWith(data).map {
      case (chs, Some(Success(items))) => applyChanges(tbl)(chs, items).sortBy(p => ProviderName.value(p.name))
      case _                           => Seq.empty[ProviderResponse]
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
      case Closed         => div()
      case CreateMode     => renderCreateModal(acc, mode, events)
      case EditMode(it)   => renderEditModal(acc, it, mode, events)
      case DeleteMode(it) => renderDeleteModal(acc, it, mode, events)
    }

    def renderTable(loaded: Boolean) = Option.when(loaded) {
      div(cls("admin-card"), tbl.render(rows))
    }

    val headerAction = div(
      child.maybe <-- Session.isAdmin.map(Option.when(_)(
        Buttons.primary.amend(dict.providersNew, onClick.mapTo(CreateMode) --> mode)
      ))
    )

    div(
      fetcher.execute(Endpoints.listProviders(acc)).map(Some(_)) --> data,
      PageHeader.render(dict.providersTitle, s"${dict.providersSubtitle} (acc #${AccountId.value(acc)})", headerAction),
      child.maybe <-- status.map(_._2),
      child.maybe <-- status.map(_._1).map(renderTable),
      child.maybe <-- Modal(opened, modalContent),
    )
  }

  private def kindSelect(current: Var[ProviderKind])(using dict: Dictionary): HtmlElement =
    select(
      cls("medulla"),
      option(value("UP"),   dict.providersKindUP),
      option(value("SAML"), dict.providersKindSAML),
      controlled(
        value <-- current.signal.map(_.toString),
        onChange.mapToValue --> { v => current.set(ProviderKind.valueOf(v)) }
      )
    )

  private def renderCreateModal(
    acc    : AccountId,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val code   = InputVar.of[ProviderCode](ProviderCode.of(""))
    val name   = InputVar.of[ProviderName](ProviderName.of(""))
    val domain = InputVar.of[Domain](Domain.of(""))
    val kind   = Var(ProviderKind.UP)
    val active = InputVar.of[Boolean](true)

    val req = InputVar.combine(Failure(Exception("")))(code.must, name.must, domain.must, active.must) { (theCode, theName, theDomain, isActive) =>
      (ProviderCode.value(theCode).isBlank, ProviderName.value(theName).isBlank, Domain.value(theDomain).isBlank) match
        case (true, _, _) => Failure(Exception(dict.providersCodeRequired))
        case (_, true, _) => Failure(Exception(dict.providersNameRequired))
        case (_, _, true) => Failure(Exception(dict.providersDomainRequired))
        case _            => Success(CreateProviderBody(theCode, theName, theDomain, kind.now(), isActive))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.createProvider(acc, r)))

    div(
      med.wire,
      med.onlySuccesses.map(Created(_)) --> events,
      med.onlySuccesses.mapTo(Closed) --> mode,
      cls("flex flex-col h-full"),
      div(
        cls("flex items-center justify-between p-6 border-b border-gray-200"),
        h2(cls("text-lg font-semibold text-admin-text"), dict.providersNew),
        button(cls("text-admin-muted hover:text-admin-text"), MaterialIcon("close"), onClick.mapTo(Closed) --> mode)
      ),
      div(
        cls("flex flex-col gap-4 p-6 flex-1"),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode), Input.basic(code)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName), Input.basic(name)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.providersDomain), Input.basic(domain)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.providersKind), kindSelect(kind)),
        div(cls("flex items-center gap-3"), Input.checkbox(active), label(cls("text-sm text-admin-text"), dict.active)),
      ),
      child <-- med.onlyErrors.map(err => div(cls("px-6 text-sm text-admin-error-fg"), err.getMessage)),
      div(
        cls("flex items-center justify-end gap-2 p-6 border-t border-gray-200"),
        Buttons.secondary.amend(dict.cancel, disabled <-- med.disabled, onClick.mapTo(Closed) --> mode),
        Buttons.primary.amend(dict.save, disabled <-- med.disabled, onClick.mapToUnit --> med.trigger),
      )
    )
  }

  private def renderEditModal(
    acc    : AccountId,
    item   : ProviderResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val code   = InputVar.of[ProviderCode](item.code)
    val name   = InputVar.of[ProviderName](item.name)
    val domain = InputVar.of[Domain](item.domain)
    val kind   = Var(item.kind)
    val active = InputVar.of[Boolean](item.active)

    val req = InputVar.combine(Failure(Exception("")))(code.must, name.must, domain.must, active.must) { (theCode, theName, theDomain, isActive) =>
      (ProviderCode.value(theCode).isBlank, ProviderName.value(theName).isBlank, Domain.value(theDomain).isBlank) match
        case (true, _, _) => Failure(Exception(dict.providersCodeRequired))
        case (_, true, _) => Failure(Exception(dict.providersNameRequired))
        case (_, _, true) => Failure(Exception(dict.providersDomainRequired))
        case _            => Success(UpdateProviderBody(theCode, theName, theDomain, kind.now(), isActive))
    }

    val med = Mediator.make(req, r => fetcher.execute(Endpoints.updateProvider(acc, item.id, r)))

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
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnCode), Input.basic(code)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.columnName), Input.basic(name)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.providersDomain), Input.basic(domain)),
        div(label(cls("block text-sm font-medium text-admin-text mb-1"), dict.providersKind), kindSelect(kind)),
        div(cls("flex items-center gap-3"), Input.checkbox(active), label(cls("text-sm text-admin-text"), dict.active)),
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
    acc    : AccountId,
    item   : ProviderResponse,
    mode   : Var[ModalMode],
    events : EventBus[CrudEvent]
  )(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val trigger = EventBus[Unit]()
    val result  = trigger.events.flatMapSwitch { _ => fetcher.execute(Endpoints.deleteProvider(acc, item.id)) }
    val busy    = Var(false)

    div(
      trigger.events.mapTo(true) --> busy,
      result --> { r =>
        busy.set(false)
        r match
          case Success(_) => events.emit(Deleted(item.id)); mode.set(Closed)
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
          p(cls("text-sm text-admin-text"), dict.deleteMessage(ProviderName.value(item.name)))
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
