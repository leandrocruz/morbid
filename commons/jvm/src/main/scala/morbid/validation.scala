package morbid

object validation {

  import guara.utils.{safeCode, safeLatinName, safeDecode}
  import zio.json.JsonDecoder
  import morbid.types.*

  // w = [a-zA-Z_0-9]
  private val domainRegex = "[\\w\\.\\-]+"  .r
  private val emailRegex  = "[\\w\\.\\-@]+" .r

  // guara safe decoders return JsonDecoder[String]; we cast to the opaque type
  private def asDecoder[T](d: JsonDecoder[String]): JsonDecoder[T] = d.asInstanceOf[JsonDecoder[T]]

  given JsonDecoder[TenantName]      = asDecoder(safeLatinName(128))
  given JsonDecoder[AccountName]     = asDecoder(safeLatinName(64))
  given JsonDecoder[ApplicationName] = asDecoder(safeLatinName(256))
  given JsonDecoder[GroupName]       = asDecoder(safeLatinName(64))
  given JsonDecoder[RoleName]        = asDecoder(safeLatinName(32))
  given JsonDecoder[PermissionName]  = asDecoder(safeLatinName(128))
  given JsonDecoder[ProviderName]    = asDecoder(safeLatinName(256))

  given JsonDecoder[TenantCode]      = asDecoder(safeCode(64))
  given JsonDecoder[AccountCode]     = asDecoder(safeCode(16))
  given JsonDecoder[ApplicationCode] = asDecoder(safeCode(16))
  given JsonDecoder[GroupCode]       = asDecoder(safeCode(16))
  given JsonDecoder[UserCode]        = asDecoder(safeCode(128))
  given JsonDecoder[RoleCode]        = asDecoder(safeCode(16))
  given JsonDecoder[PermissionCode]  = asDecoder(safeCode(16))
  given JsonDecoder[ProviderCode]    = asDecoder(safeCode(128))

  given JsonDecoder[Email]           = asDecoder(safeDecode(emailRegex, 256))
  given JsonDecoder[Domain]          = asDecoder(safeDecode(domainRegex, 256))
}
