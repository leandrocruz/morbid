package morbid.admin.views

import com.raquo.airstream.core.EventStream
import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.shared.types.UserToken
import morbid.admin.*
import morbid.admin.codec.given
import org.scalajs.dom.window

import scala.concurrent.ExecutionContext.Implicits.global

object TopBar {

  def render(using dict: Dictionary, user: UserToken[Long], fetcher: Fetcher): HtmlElement = {

    val logoutTrigger = EventBus[Unit]()

    val logoutFlow: EventStream[Unit] = logoutTrigger.events.flatMapSwitch { _ =>
      fetcher.execute(Endpoints.logoff).map[Unit](_ => window.location.reload())
    }

    div(
      cls("flex items-center gap-4 w-full"),
      logoutFlow --> Observer.empty,
      button(
        cls("hamburger"),
        onClick --> { _ => () }, // TODO: mobile menu
        MaterialIcon("menu")
      ),
      div(cls("flex-1")),
      div(
        cls("flex items-center gap-3"),
        select(
          cls("text-sm border border-admin-border rounded-sm px-2 py-1 bg-white"),
          option(value("pt_BR"), "Português"),
          option(value("en_US"), "English"),
          controlled(
            value <-- I18n.lang.signal.map(_.toString),
            onChange.mapToValue --> { v => I18n.setLang(Language.of(v)) }
          )
        ),
        div(
          cls("text-sm text-admin-muted"),
          user.email
        ),
        button(
          cls("text-sm text-admin-muted hover:text-admin-text transition-colors"),
          onClick.mapToUnit --> logoutTrigger,
          MaterialIcon("logout", "text-lg")
        )
      )
    )
  }
}
