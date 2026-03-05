package morbid.admin

import com.raquo.laminar.api.L.*
import org.scalajs.dom

sealed trait Language
case object en    extends Language
case object en_US extends Language
case object pt    extends Language
case object pt_BR extends Language

object Language {
  def of(name: String): Language = name match
    case s if s.startsWith("pt") => pt_BR
    case s if s.startsWith("en") => en_US
    case _                       => pt_BR
}

trait Dictionary {

  def language: Language

  // Login
  def loginTitle         = "Sign In"
  def loginSubtitle      = "Access the admin panel"
  def loginEmail         = "Email"
  def loginPassword      = "Password"
  def loginButton        = "Sign In"
  def loginForgot        = "Forgot your password?"

  // Sidebar
  def sidebarManagement  = "Management"
  def sidebarAccounts    = "Accounts"
  def sidebarUsers       = "Users"
  def sidebarGroups      = "Groups"
  def sidebarApps        = "Applications"
  def sidebarSecurity    = "Security"
  def sidebarProviders   = "Providers"
  def sidebarRoles       = "Roles"

  // Accounts
  def accountsTitle      = "Accounts"
  def accountsSubtitle   = "Manage system accounts"
  def accountsNew        = "New Account"

  // Users
  def usersTitle         = "Users"
  def usersSubtitle      = "Manage system users"
  def usersNew           = "New User"

  // Applications
  def appsTitle          = "Applications"
  def appsSubtitle       = "Manage system applications"

  // Groups
  def groupsTitle        = "Groups"
  def groupsSubtitle     = "Manage user groups"
  def groupsNew          = "New Group"

  // Table
  def columnApps         = "Applications"
  def columnActions      = "Actions"
  def columnCode         = "Code"
  def columnCreated      = "Created"
  def columnEmail        = "Email"
  def columnGroups       = "Groups"
  def columnId           = "Id"
  def columnName         = "Name"
  def columnRoles        = "Roles"
  def columnStatus       = "Status"

  // Common
  def active             = "Active"
  def inactive           = "Inactive"
  def edit               = "Edit"
  def delete             = "Delete"
  def save               = "Save"
  def cancel             = "Cancel"
  def close              = "Close"
  def confirm            = "Confirm"
  def deleteTitle        = "Delete Confirmation"
  def deleteMessage(name: String) = s"Are you sure you want to delete '$name'? This action cannot be undone."
  def groups             = "Groups"
  def search             = "Search..."
  def showing(n: Int)    = s"Showing $n records"
  def noRecords          = "No records found"
  def loading            = "Loading..."
  def logout             = "Logout"
}

case class English(language: Language) extends Dictionary

case class Portuguese(language: Language) extends Dictionary {

  // Login
  override def loginTitle         = "Entrar"
  override def loginSubtitle      = "Acesse o painel administrativo"
  override def loginEmail         = "Email"
  override def loginPassword      = "Senha"
  override def loginButton        = "Entrar"
  override def loginForgot        = "Esqueceu a senha?"

  // Sidebar
  override def sidebarManagement  = "Gerenciamento"
  override def sidebarAccounts    = "Contas"
  override def sidebarUsers       = "Usuários"
  override def sidebarGroups      = "Grupos"
  override def sidebarApps        = "Aplicações"
  override def sidebarSecurity    = "Segurança"
  override def sidebarProviders   = "Provedores"
  override def sidebarRoles       = "Papéis"

  // Accounts
  override def accountsTitle      = "Contas"
  override def accountsSubtitle   = "Gerencie as contas do sistema"
  override def accountsNew        = "Nova Conta"

  // Users
  override def usersTitle         = "Usuários"
  override def usersSubtitle      = "Gerencie os usuários do sistema"
  override def usersNew           = "Novo Usuário"

  // Applications
  override def appsTitle          = "Aplicações"
  override def appsSubtitle       = "Gerencie as aplicações do sistema"

  // Groups
  override def groupsTitle        = "Grupos"
  override def groupsSubtitle     = "Gerencie os grupos de usuários"
  override def groupsNew          = "Novo Grupo"

  // Table
  override def columnApps         = "Applicativos"
  override def columnName         = "Nome"
  override def columnCode         = "Código"
  override def columnEmail        = "Email"
  override def columnStatus       = "Status"
  override def columnActions      = "Ações"
  override def columnCreated      = "Criado em"

  // Common
  override def active             = "Ativo"
  override def inactive           = "Inativo"
  override def edit               = "Editar"
  override def delete             = "Excluir"
  override def save               = "Salvar"
  override def cancel             = "Cancelar"
  override def close              = "Fechar"
  override def confirm            = "Confirmar"
  override def deleteTitle        = "Confirmação de Exclusão"
  override def deleteMessage(name: String) = s"Tem certeza que deseja excluir '$name'? Esta ação não pode ser desfeita."
  override def search             = "Buscar..."
  override def showing(n: Int)    = s"Exibindo $n registros"
  override def noRecords          = "Nenhum registro encontrado"
  override def loading            = "Carregando..."
  override def logout             = "Sair"
}

object Dictionary {
  def of(lang: Language): Dictionary = lang match
    case `en` | `en_US` => English(lang)
    case `pt` | `pt_BR` => Portuguese(lang)
}

object I18n {

  private val StorageKey = "morbid-admin-lang"

  val lang: Var[Language] = Var(detectLang)

  val dictionary: Signal[Dictionary] = lang.signal.map(Dictionary.of)

  def setLang(l: Language): Unit = {
    dom.window.localStorage.setItem(StorageKey, l.toString)
    lang.set(l)
  }

  private def detectLang: Language =
    Option(dom.window.localStorage.getItem(StorageKey))
      .map(Language.of)
      .getOrElse(Language.of(dom.window.navigator.language))
}
