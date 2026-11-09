package morbid.admin.views

import com.raquo.airstream.core.EventStream
import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.shared.types.UserToken
import morbid.admin.*
import morbid.admin.api.AppAccess
import morbid.admin.codec.given
import morbid.types.ApplicationCode
import org.scalajs.dom.window

import scala.concurrent.ExecutionContext.Implicits.global

object TopBar {

  def render(using dict: Dictionary, user: UserToken[Long], fetcher: Fetcher): HtmlElement = {

    val logoutTrigger = EventBus[Unit]()

    val logoutFlow: EventStream[Unit] = logoutTrigger.events.flatMapSwitch { _ =>
      fetcher.execute(Endpoints.logoff).map[Unit](_ => window.location.reload())
    }

    /* The app selector is created once (as a val) and kept mounted for the
     * whole app lifetime. We toggle `display` instead of using `child.maybe`
     * so subscriptions to [[Session.selectedApp]] stay live even while on a
     * page that hides the selector — otherwise a programmatic
     * `Session.setSelectedApp(...)` fired before the selector re-mounts would
     * reach a freshly-constructed `<select>` whose `controlled(value <-- ...)`
     * can land on the placeholder before the options are in the DOM. */
    val appSelector = renderAppSelector
    val selectorDisplay = AdminRouter.instance.page.map(p => if appSelectorMatters(p) then "inline-flex" else "none")

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
        div(
          cls("inline-flex items-center"),
          display <-- selectorDisplay,
          appSelector,
        ),
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

  /** Routes where the "working app" context in the top-bar has meaning.
    * Account-scoped pages propagate the chosen app to per-account child
    * resources. System-wide pages and pages that already carry the app code
    * in their own URL hide the selector. */
  private def appSelectorMatters(page: Page): Boolean = page match
    case ApplicationsPage                                     => false
    case TenantsPage                                          => false
    case DashboardPage                                        => false
    case _: AccountGroupsPage | _: AppRolesPage               => false
    case _: GroupUsersPage                                    => false
    case LoginPage | _: UnknownPage                           => false
    case _                                                    => true

  /** Dropdown listing every application in the system; picking one updates
    * [[Session.selectedApp]] and so every protected admin-api call carries
    * the matching `X-Admin-App` header. */
  private def renderAppSelector(using dict: Dictionary): HtmlElement = {

    val Placeholder = "__none__"

    val selectedValue = Session.selectedApp.signal.map {
      case Some(code) => ApplicationCode.value(code)
      case None       => Placeholder
    }

    val options = Session.apps.signal.map { apps =>
      val placeholder = option(value(Placeholder), dict.selectApp)
      placeholder +: apps.map { a =>
        option(value(ApplicationCode.value(a.code)), ApplicationCode.value(a.code))
      }
    }

    select(
      cls("text-sm border border-admin-border rounded-sm px-2 py-1 bg-white"),
      children <-- options,
      controlled(
        value <-- selectedValue,
        onChange.mapToValue --> { v =>
          if v == Placeholder then Session.setSelectedApp(None)
          else Session.setSelectedApp(Some(ApplicationCode.of(v)))
        }
      )
    )
  }
}
