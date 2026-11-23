package morbid

object transformers {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.domain.token.*
  import io.scalaland.chimney.Transformer
  import io.scalaland.chimney.dsl.*

  given Transformer[RawGroup, CompactGroup]             = (original: RawGroup)       => CompactGroup(code = original.code, roles = original.roles.map(_.code))
  given Transformer[RawApplication, CompactApplication] = (original: RawApplication) => CompactApplication(id = original.details.id, code = original.details.code, groups = original.groups.map(_.transformInto[CompactGroup]))
}
