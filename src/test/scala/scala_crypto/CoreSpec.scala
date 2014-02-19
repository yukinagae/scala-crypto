package scala_crypto

import org.specs2.mutable._
import java.security.Security

class CoreSpec extends Specification {

  "scala-crypto" should {

    import Core._

    "test-encrypt-decrypt" in {

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

    "basic-password-protection" in {
      val password = "password"
      val salt = 2079324
      val algorithm = default_encrypt_password_algorithm
      val n = default_encrypt_password_n
      val encrypted_password = encrypt_password_string(password, salt, algorithm, n)

      println(s"password:${password}")
      println(s"encrypted_password:${encrypted_password}")

      encrypted_password mustNotEqual password
      encrypted_password mustEqual encrypt_password_string(password, salt, algorithm, n)
      encrypted_password mustNotEqual encrypt_password_string(password, salt, algorithm, 1)
    }

    "save-load-key-pairs" in {

      val key_pair = generate_key_pair
      val key_pair_map = get_key_pair_map(key_pair)

      println(s"key_pair_map:${key_pair_map}")

      val public_key = key_pair_map._1
      val private_key = key_pair_map._2

      public_key._1 mustEqual default_algorithm
      private_key._1 mustEqual default_algorithm

      println(s"public_key :bytes${public_key._2}")
      println(s"private_key :bytes${private_key._2}")

      val decoded_key_pair = decode_key_pair(key_pair_map)

      println(s"key_pair:${key_pair}")
      println(s"decoded_key_pair:${decoded_key_pair}")
      println(s"key_pair public:${key_pair.getPublic}")
      println(s"decoded_key_pair public:${decoded_key_pair.getPublic}")
      println(s"key_pair private:${key_pair.getPrivate}")
      println(s"decoded_key_pair private:${decoded_key_pair.getPrivate}")

      println(key_pair.getPublic == decoded_key_pair.getPublic)
      println(key_pair.getPrivate == decoded_key_pair.getPrivate)

      key_pair.getPublic mustEqual decoded_key_pair.getPublic
      key_pair.getPrivate mustEqual decoded_key_pair.getPrivate
    }

    "signature" in {

      val test_data = "Test data to sign"
      val key_pair = generate_key_pair
      val signature = sign(key_pair, test_data)

      println(signature)

      verify_signature(key_pair, test_data, signature) must beTrue

      verify_signature(generate_key_pair, test_data, signature) must beFalse

      success
    }
  }

}