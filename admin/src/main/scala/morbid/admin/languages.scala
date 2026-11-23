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
  def loginContinue      = "Continue"
  def loginSso           = "Sign in with SSO"
  def loginCancel        = "Cancel"
  def loginForgot        = "Forgot your password?"
  def loginProviderError = "Could not resolve your login provider. Check your email and try again."

  // Sidebar
  def sidebarManagement  = "Management"
  def sidebarAccounts    = "Accounts"
  def sidebarUsers       = "Users"
  def sidebarGroups      = "Groups"
  def sidebarApps        = "Applications"
  def sidebarSecurity    = "Security"
  def sidebarProviders   = "Providers"
  def sidebarRoles       = "Roles"
  def sidebarTenants     = "Tenants"
  def sidebarApiKeys     = "API Keys"

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
  def appsNew            = "New Application"

  // Tenants
  def tenantsTitle       = "Tenants"
  def tenantsSubtitle    = "Manage system tenants"
  def tenantsNew         = "New Tenant"
  def tenantsNameRequired = "Tenant name is required"
  def tenantsCodeRequired = "Tenant code is required"

  // Providers (per account)
  def providersTitle     = "Identity Providers"
  def providersSubtitle  = "Manage identity providers for this account"
  def providersNew       = "New Provider"
  def providersDomain    = "Domain"
  def providersKind      = "Kind"
  def providersKindUP    = "Username + Password"
  def providersKindSAML  = "SAML"
  def providersCodeRequired   = "Provider code is required"
  def providersNameRequired   = "Provider name is required"
  def providersDomainRequired = "Provider domain is required"

  // API Keys (service accounts per account)
  def apiKeysTitle       = "API Keys"
  def apiKeysSubtitle    = "Service accounts and tokens for this account"
  def apiKeysNew         = "New API Key"
  def apiKeysDays        = "Valid for (days)"
  def apiKeysDaysHint    = "Leave blank for the default (365 days)"
  def apiKeysIssued      = "API key issued"
  def apiKeysIssuedHint  = "Copy the token now. It will not be shown again."
  def apiKeysCopyToken   = "Copy token"
  def apiKeysRevoke      = "Revoke"
  def apiKeysRevoked     = "API key revoked"
  def apiKeysGroups      = "Groups"
  def apiKeysGroupsHint  = "Pick the groups this service account belongs to. If empty, it joins only 'all'."
  def apiKeysGroupsEmpty = "No groups available for this application on this account."
  def apiKeysSelectAppFirst = "Pick an application in the top bar to see the available groups."

  // Account apps (per-account enable/disable)
  def accountAppsTitle   = "Apps"
  def accountAppsSubtitle= "Applications enabled for this account"
  def accountAppsEnabled = "Enabled"

  // Groups
  def groupsTitle        = "Groups"
  def groupsSubtitle     = "Manage user groups"
  def groupsNew          = "New Group"
  def groupsNoApps       = "This account is not linked to any application"

  // Roles
  def rolesSubtitle      = "Roles available on this application"

  // App selector (top bar)
  def selectApp          = "Select an application"
  def selectAccount      = "Select an account"
  def noAppSelected      = "No application selected"
  def noAppSelectedHint  = "Pick an application in the top bar to start working."

  // Summary
  def summaryActive        = "active"
  def summaryInactive      = "inactive"
  def summaryTotal         = "total"

  // Filters
  def filterByName         = "Filter by name..."
  def filterByEmail        = "Filter by email..."
  def filterStatus         = "Status"
  def filterStatusAll      = "All"
  def filterStatusActive   = "Active"
  def filterStatusInactive = "Inactive"
  def filterTenant         = "Tenant"
  def filterTenantAll      = "All tenants"
  def filterKind           = "Kind"
  def filterKindAll        = "All kinds"
  def filterKindRegular    = "Regular"
  def filterKindService    = "Service account"
  def filterClear          = "Clear filters"
  def filterNoResults      = "No accounts match the selected filters"
  def filterNoUsers        = "No users match the selected filters"

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

  // Columns
  def columnTenant       = "Tenant"
  def columnUser         = "User"
  def columnPin          = "PIN"
  def columnPassword     = "Password"
  def columnKind         = "Kind"

  // Group users page
  def groupUsersTitle    = "Group users"

  // Account validation
  def accountsNameRequired   = "Account name is required"
  def accountsCodeRequired   = "Account code is required"
  def accountsTenantRequired = "Tenant is required"

  // User validation
  def usersEmailRequired     = "Email is required"
  def usersEmailInvalid      = "Email is invalid"

  // Group validation
  def groupsNameRequired     = "Group name is required"

  // Application validation
  def appsNameRequired       = "Application name is required"
  def appsCodeRequired       = "Application code is required"

  // Password and PIN
  def passwordTitle          = "Change Password"
  def passwordSubtitle       = "Choose a new password"
  def passwordRequired       = "Password is required"
  def passwordMinLength      = "Password must have at least 6 characters"
  def passwordChanged        = "Password changed"
  def passwordReset          = "Reset Password"
  def passwordResetTitle     = "Reset Password"
  def passwordResetMessage   = "Clicking the button below will generate a password reset link."
  def passwordResetInfo      = "Link created. Send it to the user so they can reset their password."
  def pinTitle               = "Set PIN"
  def pinChanged             = "PIN changed"
  def pinMinLength           = "PIN must have at least 4 digits"
  def copyLink               = "Copy Link"

  // Permissions / access
  def accessDenied           = "Access denied"
  def accessOnlyRoot         = "Only users of the root account can use the admin console"
  def loginErrorGeneric      = "Login error. Please check your credentials."

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
  override def loginContinue      = "Avançar"
  override def loginSso           = "Entrar via SSO"
  override def loginCancel        = "Cancelar"
  override def loginForgot        = "Esqueceu a senha?"
  override def loginProviderError = "Não foi possível identificar seu provedor de login. Verifique o email e tente de novo."

  // Sidebar
  override def sidebarManagement  = "Gerenciamento"
  override def sidebarAccounts    = "Contas"
  override def sidebarUsers       = "Usuários"
  override def sidebarGroups      = "Grupos"
  override def sidebarApps        = "Aplicações"
  override def sidebarSecurity    = "Segurança"
  override def sidebarProviders   = "Provedores"
  override def sidebarRoles       = "Papéis"
  override def sidebarTenants     = "Tenants"
  override def sidebarApiKeys     = "Chaves de API"

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
  override def appsNew            = "Nova Aplicação"

  // Account apps (por conta)
  override def accountAppsTitle    = "Apps"
  override def accountAppsSubtitle = "Aplicações habilitadas nesta conta"
  override def accountAppsEnabled  = "Habilitada"

  // Groups
  override def groupsTitle        = "Grupos"
  override def groupsSubtitle     = "Gerencie os grupos de usuários"
  override def groupsNew          = "Novo Grupo"
  override def groupsNoApps       = "Esta conta não está vinculada a nenhuma aplicação"

  // Roles
  override def rolesSubtitle      = "Papéis disponíveis nesta aplicação"

  // App selector (top bar)
  override def selectApp          = "Selecione uma aplicação"
  override def selectAccount      = "Selecione uma conta"
  override def noAppSelected      = "Nenhuma aplicação selecionada"
  override def noAppSelectedHint  = "Escolha uma aplicação na barra superior para começar."

  // Summary
  override def summaryActive        = "ativas/ativos"
  override def summaryInactive      = "inativas/inativos"
  override def summaryTotal         = "total"

  // Filters
  override def filterByName         = "Filtrar por nome..."
  override def filterByEmail        = "Filtrar por email..."
  override def filterStatus         = "Status"
  override def filterStatusAll      = "Todos"
  override def filterStatusActive   = "Ativas"
  override def filterStatusInactive = "Inativas"
  override def filterTenant         = "Tenant"
  override def filterTenantAll      = "Todos os tenants"
  override def filterKind           = "Tipo"
  override def filterKindAll        = "Todos os tipos"
  override def filterKindRegular    = "Regular"
  override def filterKindService    = "Conta de serviço"
  override def filterClear          = "Limpar filtros"
  override def filterNoResults      = "Nenhuma conta corresponde aos filtros selecionados"
  override def filterNoUsers        = "Nenhum usuário corresponde aos filtros selecionados"

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

  // Columns
  override def columnTenant       = "Tenant"
  override def columnUser         = "Usuário"
  override def columnPin          = "PIN"
  override def columnPassword     = "Senha"
  override def columnKind         = "Tipo"

  // Group users page
  override def groupUsersTitle    = "Usuários do grupo"

  // Account validation
  override def accountsNameRequired   = "Nome da conta é obrigatório"
  override def accountsCodeRequired   = "Código da conta é obrigatório"
  override def accountsTenantRequired = "Tenant é obrigatório"

  // User validation
  override def usersEmailRequired     = "Email é obrigatório"
  override def usersEmailInvalid      = "Email inválido"

  // Group validation
  override def groupsNameRequired     = "Nome do grupo é obrigatório"

  // Application validation
  override def appsNameRequired       = "Nome da aplicação é obrigatório"
  override def appsCodeRequired       = "Código da aplicação é obrigatório"

  // Password and PIN
  override def passwordTitle          = "Alterar senha"
  override def passwordSubtitle       = "Escolha uma nova senha"
  override def passwordRequired       = "Senha é obrigatória"
  override def passwordMinLength      = "A senha deve ter pelo menos 6 caracteres"
  override def passwordChanged        = "Senha alterada"
  override def passwordReset          = "Redefinir senha"
  override def passwordResetTitle     = "Redefinir senha"
  override def passwordResetMessage   = "Ao clicar no botão abaixo, o link para redefinição de senha será gerado."
  override def passwordResetInfo      = "Link criado. Envie-o para o usuário redefinir a senha."
  override def pinTitle               = "Definir PIN"
  override def pinChanged             = "PIN alterado"
  override def pinMinLength           = "O PIN deve ter ao menos 4 dígitos"
  override def copyLink               = "Copiar link"

  // Permissions / access
  override def accessDenied           = "Acesso negado"
  override def accessOnlyRoot         = "Somente usuários da conta raiz podem usar o console de administração"
  override def loginErrorGeneric      = "Erro de login. Verifique suas credenciais."

  // Tenants
  override def tenantsTitle           = "Tenants"
  override def tenantsSubtitle        = "Gerencie os tenants do sistema"
  override def tenantsNew             = "Novo Tenant"
  override def tenantsNameRequired    = "Nome do tenant é obrigatório"
  override def tenantsCodeRequired    = "Código do tenant é obrigatório"

  // Providers
  override def providersTitle         = "Provedores de Identidade"
  override def providersSubtitle      = "Gerencie os provedores de identidade desta conta"
  override def providersNew           = "Novo Provedor"
  override def providersDomain        = "Domínio"
  override def providersKind          = "Tipo"
  override def providersKindUP        = "Usuário + Senha"
  override def providersKindSAML      = "SAML"
  override def providersCodeRequired  = "Código do provedor é obrigatório"
  override def providersNameRequired  = "Nome do provedor é obrigatório"
  override def providersDomainRequired = "Domínio do provedor é obrigatório"

  // API Keys
  override def apiKeysTitle           = "Chaves de API"
  override def apiKeysSubtitle        = "Contas de serviço e tokens desta conta"
  override def apiKeysNew             = "Nova Chave"
  override def apiKeysDays            = "Validade (dias)"
  override def apiKeysDaysHint        = "Deixe em branco para o padrão (365 dias)"
  override def apiKeysIssued          = "Chave de API emitida"
  override def apiKeysIssuedHint      = "Copie o token agora. Ele não será mostrado novamente."
  override def apiKeysCopyToken       = "Copiar token"
  override def apiKeysRevoke          = "Revogar"
  override def apiKeysRevoked         = "Chave de API revogada"
  override def apiKeysGroups          = "Grupos"
  override def apiKeysGroupsHint      = "Selecione os grupos aos quais esta conta de serviço pertence. Se vazio, entra apenas no grupo 'all'."
  override def apiKeysGroupsEmpty     = "Nenhum grupo disponível para esta aplicação nesta conta."
  override def apiKeysSelectAppFirst  = "Selecione uma aplicação na barra superior para ver os grupos disponíveis."
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
