package morbid.ui

import com.raquo.laminar.api.L
import com.raquo.laminar.api.L.*
import scala.collection.mutable

object DataTable {

  case class Column[V](
    header : String,
    render : V => HtmlElement,
    cls    : String = ""
  )

  trait Row[K, V] {
    def highlight(active: Boolean): Unit
    def disable(active: Boolean): Unit
  }

  case class RowState[K, V](key: K, highlighted: Var[Boolean], disabled: Var[Boolean]) extends Row[K, V] {
    override def highlight(active: Boolean) = highlighted.set(active)
    override def disable(active: Boolean)   = disabled.set(active)
  }

  trait Table[K, V] {
    def render(items : Signal[Seq[V]]): HtmlElement
    def row(key: K): Option[Row[K, V]]
  }

  def simple[K, V](columns: Seq[Column[V]], key: V => K): Table[K, V] = SimpleTable(columns, key)

  private case class SimpleTable[K, V](columns: Seq[Column[V]], key: V => K) extends Table[K, V] {

    private val cache = mutable.Map.empty[K, RowState[K, V]]

    private def ensureRow(key: K): RowState[K, V] = {
      cache.getOrElseUpdate(key, RowState(key, Var(false), Var(false)))
    }

    override def row(key: K) = cache.get(key)

    override def render(items : Signal[Seq[V]]) = {

      def renderRow(key: K, initial: V, value: Signal[V]): HtmlElement = {

        def renderColumn(state: RowState[K, V])(col: Column[V]) = {
          td(
            cls("medulla"),
            cls(col.cls),
            child <-- value.map(col.render)
          )
        }

        val state = ensureRow(key)
        tr(
          cls("medulla"),
          cls.toggle("highlight") <-- state.highlighted,
          cls.toggle("disabled")  <-- state.disabled,
          columns.map(renderColumn(state))
        )
      }

      table(
        cls("medulla"),
        thead(
          tr(columns.map(col => th(cls(col.cls), col.header)))
        ),
        tbody(
          children <-- items.split(key)(renderRow)
        ),
      )
    }
  }

}