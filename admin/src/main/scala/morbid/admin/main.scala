package morbid.admin

import com.raquo.laminar.api.L.renderOnDomContentLoaded
import medulla.config.MedullaConfig
import medulla.fetch.*
import medulla.login.{LocalLogout, LoginHelper, Logout}
import medulla.render.AppRender
import medulla.{DefaultMedullaApp, MedullaApp, config}
import org.scalajs.dom.document
import wvlet.airframe.*

@main
def main(): Unit = {

  type UID = Long

  val medullaConfig = config.DefaultMedullaConfig(
    name  = "Morbid Admin",
    fetch = config.FetchConfig("http://localhost:9000"),
    login = config.LoginConfig(5000),
  )

  newDesign
    .bind [MedullaConfig   ] .toInstance(medullaConfig)
    .bind [Logout]           .to[LocalLogout]
    .bind [Handler]          .toProvider { (logout: Logout) => LogHandler(AuthAwareHandler[UID](JsonHandler(), logout)) }
    .bind [Fetcher]          .to[BasicFetcher]
    .bind [LoginHelper[UID]] .to[AdminLoginHelper]
    .bind [AppRender  [UID]] .to[AdminAppRender]
    .bind [MedullaApp      ] .to[DefaultMedullaApp[UID]]
    .build[MedullaApp] { app =>
      lazy val container = document.getElementById("app")
      renderOnDomContentLoaded(container, app.rootElement)
    }
}
