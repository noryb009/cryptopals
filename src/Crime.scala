import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

import scala.annotation.tailrec
import scala.util.Random

object Crime {
  def formatRequest(session: String, p: String): String =
    s"""POST / HTTP/1.1
       |Host: hapless.com
       |Cookie: sessionid=$session
       |Content-Length: ${p.length}
       |
     """.stripMargin ++ p

  def compress(b: String): Seq[Byte] = {
    val outStream = new ByteArrayOutputStream
    val out = new GZIPOutputStream(outStream)
    out.write(Utils.stringToBinary(b).toArray)
    out.close()
    outStream.toByteArray
  }

  def oracleInner(session: String, p: String): Seq[Byte] =
    compress(formatRequest(session, p))

  type Oracle = String => Int

  /* Note that encrypting using CTR, and using CBC (after padding) doesn't change the length.
   * The encryption can be removed.
   */
  def oracle(session: String)(p: String): Int = {
    val key = AES.genKeyStream(AES.randomString(16), AES.randomBytes(8).toArray)
    val t = oracleInner(session, p)
    AES.encryptCTR(oracleInner(session, p), key).length
  }

  def oracleCBC(session: String)(p: String): Int = {
    val key = AES.randomString(16)
    val iv = AES.randomBytes(16)
    AES.encryptCBC(AES.padPKCS7(oracleInner(session, p)), key, Some(iv)).length
  }

  type AssertCorrect = String => Unit

  /* We want to encourage a long backwards reference, since then the
   * new character will compress into that block as well. So we include
   * the entire header up until the first session ID character as a
   * prefix.
   *
   * Next up is the bits: adding one to the backwards reference will be
   * either zero or one extra bits, while adding a character will almost
   * certainly be at least two. The character that doesn't increase the
   * byte count is assumed to be the next byte. We add an extra prefix
   * before the above mentioned prefix to move around the location of
   * the last character bits.
   *
   * This takes an AssertCorrect parameter - this is simply a way to stop
   * an incorrect byte causing an infinite loop.
   */
  def attack(oracle: Oracle, assertCorrect: AssertCorrect): String = {
    val splitAt = "aaaaa"
    val secondPrefix = formatRequest(splitAt, "").split(splitAt)(0)
    val startPossible = Base64.chars + "=" + "\n"

    @tailrec
    def filterPossible(sessionID: String, acc: String = "", possible: String = startPossible): Char = {
      // TODO: length
      val prefix = acc + "\n" ++ sessionID
      val startLen = oracle(prefix)
      val result = possible.filter(c => oracle(prefix :+ c) == startLen)
      if(result.isEmpty && acc.length > 100) // Ruled out everything, start again. :(
        filterPossible(sessionID)
      else if(result.isEmpty)
        filterPossible(sessionID, AES.randomString(1) ++ acc)
      else if(result.length == 1) // Found it!
        result.head
      else // Keep filtering.
        filterPossible(sessionID, AES.randomString(1) ++ acc, possible)
    }

    /* There may be false positives. So we repeat until we get the same thing
     * n times.
     */
    val n = 2
    @tailrec
    def inner(acc: String): String = {
      assertCorrect(acc)
      //println(acc)
      val prefix = secondPrefix ++ acc

      @tailrec
      def repeatFilterPossible(history: String = ""): Char = { // Should be a MultiSet, but oh well.
        val c = filterPossible(prefix)
        if(history.count(_ == c) + 1 == n)
          c
        else
          repeatFilterPossible(c +: history)
      }

      val c = repeatFilterPossible()
      if (c == '\n')
        acc
      else
        inner(acc :+ c)
    }
    inner("")
  }
}
