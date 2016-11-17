import java.io.IOException

import scala.annotation.tailrec
import scala.io.Source

object TimingAttack {
  val url = "http://localhost:8080"

  def trySig(signature: String): Boolean = {
    try {
      Source.fromURL(url + "?file=myfile&signature=" + signature).mkString
      true
    } catch {
      case e: IOException if e.getMessage.contains("500") => false
    }
  }

  def timeSig(signature: String): (Boolean, Long) = {
    val start = System.currentTimeMillis()
    val result = trySig(signature)
    val end = System.currentTimeMillis()
    (result, end - start)
  }

  val possible = "0123456789abcdef"

  def getSig: Option[String] = {
    @tailrec
    def getSigDigit(acc: String): Option[String] = {
      if(acc.length > 20)
        None
      else {
        val results = possible.map(acc + _).map{sig =>
          val (res, time) = timeSig(sig)
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

    timeSig("") // warm up
    getSigDigit("")
  }
}
