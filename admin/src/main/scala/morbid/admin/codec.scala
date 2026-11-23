package morbid.admin

object codec {

  import medulla.fetch.{RequestEncoder, ResponseDecoder}
  import zio.json.{JsonDecoder, JsonEncoder}
  import scala.util.{Failure, Success, Try}

  given zioJsonRequestEncoder[T: JsonEncoder]: RequestEncoder[T] with
    def encode(i: T): Try[String] = Success(JsonEncoder[T].encodeJson(i, None).toString)

  given zioJsonResponseDecoder[T: JsonDecoder]: ResponseDecoder[T] with
    def decode(text: String): Try[T] =
      JsonDecoder[T].decodeJson(text) match
        case Right(v) => Success(v)
        case Left(e)  => Failure(new RuntimeException(s"JSON decode error: $e"))
}

object converters {

  import morbid.types.*
  import medulla.ui.inputs.SafeConverter
  import scala.util.Try

  given SafeConverter[ApplicationCode] = new SafeConverter[ApplicationCode] {
    override def fromText(str: String)      = Try(ApplicationCode.of(str))
    override def asText(t: ApplicationCode) = Try(ApplicationCode.value(t))
  }

  given SafeConverter[ApplicationName] = new SafeConverter[ApplicationName] {
    override def fromText(str: String)      = Try(ApplicationName.of(str))
    override def asText(t: ApplicationName) = Try(ApplicationName.value(t))
  }

  given SafeConverter[AccountCode] = new SafeConverter[AccountCode] {
    override def fromText(str: String)  = Try(AccountCode.of(str))
    override def asText(t: AccountCode) = Try(AccountCode.value(t))
  }

  given SafeConverter[AccountName] = new SafeConverter[AccountName] {
    override def fromText(str: String)  = Try(AccountName.of(str))
    override def asText(t: AccountName) = Try(AccountName.value(t))
  }

  given SafeConverter[GroupCode] = new SafeConverter[GroupCode] {
    override def fromText(str: String) = Try(GroupCode.of(str))
    override def asText(t: GroupCode)  = Try(GroupCode.value(t))
  }

  given SafeConverter[GroupName] = new SafeConverter[GroupName] {
    override def fromText(str: String) = Try(GroupName.of(str))
    override def asText(t: GroupName)  = Try(GroupName.value(t))
  }

  given SafeConverter[UserCode] = new SafeConverter[UserCode] {
    override def fromText(str: String) = Try(UserCode.of(str))
    override def asText(t: UserCode)   = Try(UserCode.value(t))
  }

  given SafeConverter[Email] = new SafeConverter[Email] {
    override def fromText(str: String) = Try(Email.of(str))
    override def asText(t: Email)      = Try(Email.value(t))
  }

  given SafeConverter[Password] = new SafeConverter[Password] {
    override def fromText(str: String) = Try(Password.of(str))
    override def asText(t: Password)   = Try(Password.value(t))
  }

  given SafeConverter[Pin] = new SafeConverter[Pin] {
    override def fromText(str: String) = Try(Pin.of(str))
    override def asText(t: Pin)        = Try(Pin.value(t))
  }

  given SafeConverter[TenantCode] = new SafeConverter[TenantCode] {
    override def fromText(str: String) = Try(TenantCode.of(str))
    override def asText(t: TenantCode) = Try(TenantCode.value(t))
  }

  given SafeConverter[TenantName] = new SafeConverter[TenantName] {
    override def fromText(str: String) = Try(TenantName.of(str))
    override def asText(t: TenantName) = Try(TenantName.value(t))
  }

  given SafeConverter[ProviderCode] = new SafeConverter[ProviderCode] {
    override def fromText(str: String) = Try(ProviderCode.of(str))
    override def asText(t: ProviderCode) = Try(ProviderCode.value(t))
  }

  given SafeConverter[ProviderName] = new SafeConverter[ProviderName] {
    override def fromText(str: String) = Try(ProviderName.of(str))
    override def asText(t: ProviderName) = Try(ProviderName.value(t))
  }

  given SafeConverter[Domain] = new SafeConverter[Domain] {
    override def fromText(str: String) = Try(Domain.of(str))
    override def asText(t: Domain)     = Try(Domain.value(t))
  }
}
