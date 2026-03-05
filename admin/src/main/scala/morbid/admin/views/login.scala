package morbid.admin.views

import com.raquo.laminar.api.L.*
import medulla.ui.{Input, Buttons}
import medulla.ui.inputs.{InputVar, InputType, given}
import morbid.admin.*

object LoginView {

  def render(using dict: Dictionary): HtmlElement = {

    val emailVar    = InputVar.of[String]
    val passwordVar = InputVar.of[String]

    div(
      cls("flex items-center justify-center min-h-screen bg-admin-bg"),
      div(
        cls("login-card"),
        div(
          cls("text-center mb-8"),
          div(cls("font-mono font-bold text-2xl text-admin-text mb-2"), dict.loginTitle),
          div(cls("text-sm text-admin-muted"), dict.loginSubtitle),
        ),
        form(
          cls("flex flex-col gap-4"),
          onSubmit.preventDefault --> { _ =>
            // TODO: implement actual login
            AdminRouter.instance.navigateTo(AccountsPage)
          },
          div(
            label(cls("block text-sm font-medium text-admin-text mb-1"), dict.loginEmail),
            Input.basic(emailVar).node
          ),
          div(
            label(cls("block text-sm font-medium text-admin-text mb-1"), dict.loginPassword),
            Input.basic(passwordVar, kind = Signal.fromValue(InputType.password)).node
          ),
          div(
            cls("mt-2"),
            Buttons.primary.amend(
              cls("w-full"),
              typ("submit"),
              dict.loginButton
            )
          ),
          div(
            cls("text-center mt-2"),
            a(
              cls("text-sm text-admin-muted hover:text-admin-accent transition-colors cursor-pointer"),
              dict.loginForgot
            )
          )
        )
      )
    )
  }
}
