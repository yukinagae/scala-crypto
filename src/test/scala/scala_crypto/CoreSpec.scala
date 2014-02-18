package scala_crypto

import org.specs2.mutable._
import java.security.Security

class CoreSpec extends Specification {

  "scala-crypto" should {
    "test-encrypt-decrypt" in {

      import Core._

      val key_pair = generate_key_pair
      val data = "secret text"

      println(s"private:${key_pair.getPrivate}")
      println(s"public:${key_pair.getPublic}")
      println(s"private algorithm:${key_pair.getPrivate.getAlgorithm}")
      println(s"public algorithm:${key_pair.getPublic.getAlgorithm}")
      println(s"private format:${key_pair.getPrivate.getFormat}")
      println(s"public format:${key_pair.getPublic.getFormat}")
      println(s"private encoded:${key_pair.getPrivate.getEncoded}")
      println(s"public encoded:${key_pair.getPublic.getEncoded}")

      key_pair must not beNull

      val encrypted_text = encrypt(key_pair.getPublic, data)

      encrypted_text must not beNull

      val decrypted_text = decrypt(key_pair.getPrivate, encrypted_text)

      decrypted_text must not beNull

      println(decrypted_text)

      decrypted_text mustEqual data
    }
  }

}