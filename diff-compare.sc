//> using scala "3.3.3"
//> using dep "com.github.pathikrit::better-files:3.9.2"
//> using dep "com.github.tototoshi::scala-csv:2.0.0"
//> using dep "org.apache.commons:commons-text:1.14.0"

import com.github.tototoshi.csv.*
import better.files.*
import org.apache.commons.text.similarity.LevenshteinDistance

case class Line(
  //number  : Int,
  account : Long,
  //name    : String,
  uid     : Long,
  email   : String,
)

sealed trait Diff {
  def item: Line
  def order: Int
}
case class OnlyOnMorby   (item: Line)                        extends Diff { override def order: Int = 2}
case class AccountChanged(item: Line, orig: Line)            extends Diff { override def order: Int = 0}
case class UserChanged   (item: Line, orig: Line)            extends Diff { override def order: Int = 1}
case class EmailChanged  (item: Line, orig: Line, size: Int) extends Diff { override def order: Int = 3}

def toLine(data: Map[String, String], index: Int) = Line(
  //number    = index,
  account   = data("id").toLong,
  //name      = data("name"),
  uid       = data("uid").toLong,
  email     = data("email")
)

def load(file: String) = {
  CSVReader
    .open(File(file).toJava)
    .allWithHeaders()
    .zipWithIndex.map(toLine)
    .filter(_.account != 1)
    .filter(_.account != 25)
    .toSeq
}

def whenNone(o4: Seq[Line], item: Line) = o4.find(it => it.account == item.account && it.uid == item.uid && it.email != item.email).map(it => EmailChanged(item, it, LevenshteinDistance.getDefaultInstance.apply(it.email, item.email))).getOrElse(OnlyOnMorby   (item)) 

def whenUserChanged(o4: Seq[Line], mb: Seq[Line], item: Line, orig: Line) = {
  
  // val onO4 = o4.find(_.uid == item.uid)
  // val onMb = mb.find(_.uid == item.uid)
  
  UserChanged(item, orig)
}

val o4     = load("/Users/leandro/dev/projects/morbid/o4.csv")
val morbid = load("/Users/leandro/dev/projects/morbid/morbid.csv")
val inter  = o4.intersect(morbid)

val onlyO4 = o4    .filterNot(inter.contains)
val onlyMb = morbid.filterNot(inter.contains)

println(s"O4 ${onlyO4.length}")
println(s"Morbid ${onlyMb.length}")
println(s"Intersect: ${inter.length}")

val diff = onlyMb.map { item =>
  o4.find(_.email == item.email) match
    case None                                       => whenNone(onlyO4, item)
    case Some(orig) if orig.account != item.account => AccountChanged(item, orig)
    case Some(orig) if orig.uid != item.uid         => whenUserChanged(onlyO4, onlyMb, item, orig)
}

val max = diff.map(_.item.email.length()).max
diff.sortWith(_.order < _.order).zipWithIndex.foreach { 
  case (OnlyOnMorby   (item      )     , idx) => println(s"[${(idx + 1).toString.padTo(3, " ").mkString}] Morbid  ${item.email.padTo(max, " ").mkString} => account: ${item.account}, uid: ${item.uid}")
  case (AccountChanged(item, orig)     , idx) => println(s"[${(idx + 1).toString.padTo(3, " ").mkString}] Account ${item.email.padTo(max, " ").mkString} => orig: ${orig.account}, morbid: ${item.account}")
  case (UserChanged   (item, orig)     , idx) => println(s"[${(idx + 1).toString.padTo(3, " ").mkString}] User    ${item.email.padTo(max, " ").mkString} => orig: ${orig.uid}, morbid: ${item.uid}")
  case (EmailChanged  (item, orig, len), idx) => println(s"[${(idx + 1).toString.padTo(3, " ").mkString}] Email   ${item.email.padTo(max, " ").mkString} => [diff $len] was ${orig.email} (${orig.uid})")
}

diff.sortWith(_.order < _.order).foreach { 
  case EmailChanged (item, orig, len) if len <=3 => println(s"update users set email = '${orig.email}' where id = ${orig.uid};")
  case _ =>
}





// val writer = CSVWriter.open(File("report.csv").toJava)
// writer.writeRow(List("ANO","MÊS","TEMPO MÉDIO POR ÍTEM (s)", "ÍTENS", "TOTAL (s)"))
// points.foreach { point =>
//   writer.writeRow(List(point.my.year, point.my.month, point.average, point.count, point.count*point.average))
// }
// writer.close()
