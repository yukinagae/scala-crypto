package scala_crypto

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Key

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

  def private_key(keyPair: KeyPair): PrivateKey = {
    keyPair.getPrivate
  }

  def as_private_key(key: Key): PrivateKey = {
    key match {
      // TODO case k: KeyPair 
      case k: PrivateKey => k
      case _ => throw new RuntimeException(s"Dont't know how to convert to private key: ${key}")
    }
  }

  def public_key(keyPair: KeyPair): PublicKey = {
    keyPair.getPublic
  }

  def as_public_key(key: Key): PublicKey = {
    key match {
      // TODO case k: KeyPair
      case k: PublicKey => k
      case _ => throw new RuntimeException(s"Dont't know how to convert to public key: ${key}")
    }
  }

  def algorithm(key: Key): String = {
    key.getAlgorithm
  }

  def encoded(key: Key): Array[Byte] = {
    key.getEncoded
  }

  def format(key: Key): String = {
    key.getFormat
  }

  // TODO def create-cipher 
  
  
  
}
