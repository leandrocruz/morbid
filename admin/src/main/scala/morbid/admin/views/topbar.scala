package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.shared.types.UserToken
import morbid.admin.*

object TopBar {

  def render(using dict: Dictionary, user: UserToken[Long]): HtmlElement = {
    div(
      cls("flex items-center gap-4 w-full"),
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
          onClick --> { _ => org.scalajs.dom.window.location.href = "/logout" },
          MaterialIcon("logout", "text-lg")
        )
      )
    )
  }
}
