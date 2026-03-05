package morbid.admin.views

import com.raquo.laminar.api.L.*
import morbid.admin.*

object Sidebar {

  case class SidebarSection(label: String, links: Seq[(String, String, Page)])

  def render(using dict: Dictionary): HtmlElement = {

    val sections = Seq(
      SidebarSection(
        dict.sidebarManagement,
        Seq(
          (dict.sidebarApps,     "apps",      ApplicationsPage),
          (dict.sidebarAccounts, "apartment", AccountsPage),
          (dict.sidebarUsers,    "group",     UsersPage),
        )
      ),
      SidebarSection(
        dict.sidebarSecurity,
        Seq(
          (dict.sidebarProviders, "key",                  ProvidersPage),
          (dict.sidebarRoles,     "admin_panel_settings", RolesPage),
        )
      ),
    )

    val openSections = sections.map(s => s.label -> Var(true)).toMap

    div(
      cls("flex flex-col gap-1 mt-2"),
      sections.map { section =>
        val isOpen = openSections(section.label)
        renderSection(section, isOpen)
      }
    )
  }

  private def renderSection(section: SidebarSection, isOpen: Var[Boolean]): HtmlElement = {
    div(
      cls("sidebar-section"),
      div(
        cls("section-header"),
        onClick --> { _ => isOpen.update(!_) },
        span(section.label),
        svg.svg(
          svg.cls <-- isOpen.signal.map(o => "chevron" + (if o then " open" else "")),
          svg.viewBox("0 0 24 24"),
          svg.fill("none"),
          svg.stroke("currentColor"),
          svg.strokeWidth("2"),
          svg.path(svg.d("M9 5l7 7-7 7"))
        )
      ),
      div(
        cls("section-links"),
        display <-- isOpen.signal.map(if _ then "" else "none"),
        section.links.map { (label, icon, page) =>
          div(
            cls <-- AdminRouter.instance.page.map(cp => "nav-link" + (if cp == page then " active" else "")),
            AdminRouter.instance.linkTo(page),
            MaterialIcon(icon),
            span(label)
          )
        }
      )
    )
  }
}
