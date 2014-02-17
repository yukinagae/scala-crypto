package scala_crypto

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.KeyPair

object Core {

  val default_algorithm = "RSA"
  val default_signature_algorithm = "SHA1withRSA"
  val default_transformation = "RSA/None/NoPadding"
  val default_provider = "BC"
  val default_character_encoding = "UTF-8"
  val default_encrypt_password_algorithm = "SHA-256"
  val default_encrypt_password_n = 1000

  Security.addProvider(new BouncyCastleProvider)

  def generate_key_pair(): KeyPair = {
    val key_pair_generator = KeyPairGenerator.getInstance(default_algorithm)
    key_pair_generator.initialize(1024)
    key_pair_generator.generateKeyPair
  }

}
