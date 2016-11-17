import java.io.IOException

import scala.annotation.tailrec
import scala.io.Source

object TimingAttack {
  val url = "http://localhost:8080"

  def trySig(sleep: Int, signature: String): Boolean = {
    try {
      Source.fromURL(url + "?file=myfile&sleep=" + sleep + "&signature=" + signature).mkString
      true
    } catch {
      case e: IOException if e.getMessage.contains("500") => false
    }
  }

  def timeSig(sleep: Int, signature: String): (Boolean, Long) = {
    val start = System.currentTimeMillis()
    val result = trySig(sleep, signature)
    val end = System.currentTimeMillis()
    (result, end - start)
  }

  def timeSigMedian(sleep: Int, num: Int, signature: String): (Boolean, Long) = {
    val first = timeSig(sleep, signature)
    if(first._1)
      first
    else {
      val times = (first +: (1 until num).map(_ => timeSig(sleep, signature))).map(_._2).sorted
      (false, times(times.length/2))
    }
  }

  val possible = "0123456789abcdef"

  def getSigFast(sleep: Int = 50, num: Int = 1): Option[String] = {
    @tailrec
    def getSigDigit(acc: String): Option[String] = {
      if(acc.length > 20)
        None
      else {
        val results = possible.map(acc + _).map{sig =>
          val (res, time) = timeSigMedian(sleep, num, sig)
          (res, time, sig)
        }
        val max = results.max
        max match {
          case (result, time, sig) =>
            if(result)
              Some(sig)
            else
              getSigDigit(sig)
        }
      }
    }

    timeSig(sleep, "") // warm up
    getSigDigit("")
  }

  def getSig: Option[String] = {
    getSigFast(50, 1)
  }
}
