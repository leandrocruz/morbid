package morbid

object transformers {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.domain.token.*
  import io.scalaland.chimney.Transformer
  import io.scalaland.chimney.dsl.*

  // Delegam para os construtores de domain.token, que montam groups E plans. Um Transformer
  // escrito à mão aqui já deixou os planos de fora do token (v3.0.0/v3.0.1).
  given Transformer[RawGroup, CompactGroup]             = CompactGroup.of(_)
  given Transformer[RawApplication, CompactApplication] = CompactApplication.of(_)
}
