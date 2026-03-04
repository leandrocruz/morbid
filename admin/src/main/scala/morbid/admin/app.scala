package morbid.admin

import com.raquo.laminar.api.L.*
import com.raquo.waypoint.*
import medulla.fetch.Fetcher
import medulla.login.DefaultLoginHelper
import medulla.render.BaseAppRender
import medulla.router.{MedullaRouter, PageCodec}
import medulla.shared.types.{GlobalAppData, UserToken}
import medulla.ui.layout.SimpleGridLayout
import morbid.admin.views.*
import com.raquo.airstream.core.EventStream

import scala.util.Success

// -- Page ADT --

sealed trait Page
case object LoginPage                extends Page
case object AccountsPage             extends Page
case object UsersPage                extends Page
case object GroupsPage               extends Page
case object ApplicationsPage          extends Page
case object RolesPage                extends Page
case class  UnknownPage(path: String) extends Page

// -- App Data --

case class AdminData(name: String) extends GlobalAppData

// -- Login Helper --

case class AdminLoginHelper(fetcher: Fetcher) extends DefaultLoginHelper {
  override def retrieve = {
    // Check if user is logged in by verifying token cookie
    EventStream.delay(100).map(_ => Some(new UserToken[Long] {
      def id    = 1L
      def name  = "Admin"
      def email = "admin@morbid.dev"
    }))
  }
}

// -- Router --

object AdminRouter {

  given PageCodec[Page] = new PageCodec[Page] {

    override def encodePage(page: Page) = page match
      case LoginPage       => "login"
      case AccountsPage    => "accounts"
      case UsersPage       => "users"
      case GroupsPage      => "groups"
      case ApplicationsPage => "applications"
      case RolesPage       => "roles"
      case UnknownPage(s)  => s"unknown:$s"

    override def decodePage(data: String) = data match
      case "login"    => LoginPage
      case "accounts"     => AccountsPage
      case "users"        => UsersPage
      case "groups"       => GroupsPage
      case "applications" => ApplicationsPage
      case "roles"        => RolesPage
      case other      => UnknownPage(other)
  }

  val routes: Seq[Route[? <: Page, ?]] = Seq(
    Route.static(LoginPage,    root / "login"),
    Route.static(AccountsPage, root / "accounts"),
    Route.static(UsersPage,    root / "users"),
    Route.static(GroupsPage,        root / "groups"),
    Route.static(ApplicationsPage, root / "applications"),
    Route.static(RolesPage,        root / "roles"),
    Route.static(AccountsPage, root),
  )

  val instance = new MedullaRouter[Page](UnknownPage.apply)(routes*) {
    override def title(page: Page) = "Morbid Admin"
  }
}

// -- App Render --

case class AdminAppRender(fetcher: Fetcher) extends BaseAppRender[AdminData, Long] {

  override def loadAppData = EventStream.delay(100).map(_ => Success(AdminData("Morbid Admin")))

  override def whenLoggedOut = LoginView.render

  override def appLoaded(data: AdminData)(using user: UserToken[Long]) = {

    def main = {
      AdminRouter.instance.render {
        case LoginPage        => LoginView.render
        case AccountsPage     => div(child <-- I18n.dictionary.map { dict => given Dictionary = dict; AccountsView.render })
        case UsersPage        => div(child <-- I18n.dictionary.map { dict => given Dictionary = dict; UsersView.render })
        case GroupsPage       => div(child <-- I18n.dictionary.map { dict => given Dictionary = dict; GroupsView.render })
        case ApplicationsPage => div(child <-- I18n.dictionary.map { dict => given Dictionary = dict; ApplicationsView.render(fetcher) })
        case RolesPage        => div("Roles")
        case UnknownPage(p)   => div(s"Página não encontrada: $p")
      }
    }

    def left = I18n.dictionary.map { dict =>
      given Dictionary = dict
      Sidebar.render
    }

    def logo = Signal.fromValue(
      div(cls("admin-logo"), "Morbid")
    )

    def top = I18n.dictionary.map { dict =>
      given Dictionary = dict
      TopBar.render
    }

    SimpleGridLayout(logo, top, left, main).render
  }
}
