import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object AES {
  def decrypt(data: Seq[Byte], key: String): Seq[Byte] = {
    val key = "YELLOW SUBMARINE"
    val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes, "AES"))
    c.doFinal(data.toArray)
  }
}
