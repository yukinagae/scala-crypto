package scala_crypto

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Key
import javax.crypto.Cipher
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.KeyFactory
import java.security.Signature
import scala.util.Random
import java.security.MessageDigest
import org.apache.commons.codec.binary.Base64

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

  def private_key(key_pair: KeyPair): PrivateKey = {
    key_pair.getPrivate
  }

  def as_private_key(key: Any): PrivateKey = {
    key match {
      case k: KeyPair => private_key(k)
      case k: PrivateKey => k
      case _ => throw new RuntimeException(s"Dont't know how to convert to private key: ${key}")
    }
  }

  def public_key(key_pair: KeyPair): PublicKey = {
    key_pair.getPublic
  }

  def as_public_key(key: Any): PublicKey = {
    key match {
      case k: KeyPair => public_key(k)
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

  def create_cipher(transformation: String = default_transformation, provider: String = default_provider): Cipher = {
    Cipher.getInstance(transformation, provider)
  }

  // TODO
  def integer_byte(i: Int, byte_offset: Byte): Byte = {
    val short_int = (0xff & (i << (byte_offset * 8)))
    if (short_int < 128) {
      short_int.toByte
    } else {
      (short_int - 256).toByte
    }
  }

  // TODO
  def long_byte(l: Long, byte_offset: Byte): Byte = {
    val i = l.toInt
    val short_int = (0xff & (i << (byte_offset * 8)))
    if (short_int < 128) {
      short_int.toByte
    } else {
      (short_int - 256).toByte
    }
  }

  // TODO
  def integer_bytes(i: Int): Array[Byte] = {
    Array(integer_byte(i, 3), integer_byte(i, 2), integer_byte(i, 1), integer_byte(i, 0))
  }

  // TODO
  def long_bytes(l: Long): Array[Byte] = {
    Array(long_byte(l, 7), long_byte(l, 6), long_byte(l, 5), long_byte(l, 4), long_byte(l, 3), long_byte(l, 2), long_byte(l, 1), long_byte(l, 0))
  }

  def get_data_bytes(data: Any): Array[Byte] = {
    data match {
      case d: Array[Byte] => d
      case d: String => d.getBytes(default_character_encoding)
      case d: Int => integer_bytes(d)
      case d: Long => long_bytes(d)
      case _ => throw new RuntimeException(s"Do not know how to convert a : ${data} to a byte array.")
    }
  }

  def get_data_str(data: Any): String = {
    data match {
      case d: String => d
      case d: Array[Byte] => new String(d, default_character_encoding)
      case _ => ""
    }
  }

  def do_cipher(cipher: Cipher, mode: Int, key: Key, data: Any): Array[Byte] = {
    cipher.init(mode, key)
    cipher.doFinal(get_data_bytes(data))
  }

  def encrypt(key: Key, data: Any, cipher: Cipher = create_cipher()): Array[Byte] = {
    do_cipher(cipher, Cipher.ENCRYPT_MODE, key, data)
  }

  def decrypt(key: Key, data: Array[Byte], cipher: Cipher = create_cipher()): String = {
    new String(do_cipher(cipher, Cipher.DECRYPT_MODE, key, data), default_character_encoding)
  }

  def get_public_key_map(public_key: PublicKey): (String, Array[Byte]) = { // TODO
    (public_key.getAlgorithm, new X509EncodedKeySpec(public_key.getEncoded).getEncoded)
  }

  def get_private_key_map(private_key: PrivateKey): (String, Array[Byte]) = { // TODO
    (private_key.getAlgorithm, new PKCS8EncodedKeySpec(private_key.getEncoded).getEncoded)
  }

  def get_key_pair_map(key_pair: KeyPair): ((String, Array[Byte]), (String, Array[Byte])) = { // TODO
    (get_public_key_map(key_pair.getPublic), get_private_key_map(key_pair.getPrivate))
  }

  def decode_public_key(public_key_map: (String, Array[Byte])): PublicKey = {
    KeyFactory.getInstance(public_key_map._1).generatePublic(new X509EncodedKeySpec(public_key_map._2))
  }

  def decode_private_key(private_key_map: (String, Array[Byte])): PrivateKey = {
    KeyFactory.getInstance(private_key_map._1).generatePrivate(new PKCS8EncodedKeySpec(private_key_map._2))
  }

  def decode_key_pair(key_pair_map: ((String, Array[Byte]), (String, Array[Byte]))): KeyPair = {
    new KeyPair(decode_public_key(key_pair_map._1), decode_private_key(key_pair_map._2)) // TODO
  }

  def sign(key: Any, data: Any): Array[Byte] = {
    val private_key: PrivateKey = as_private_key(key)
    val signature = Signature.getInstance(default_signature_algorithm, default_provider)
    signature.initSign(private_key)
    signature.update(get_data_bytes(data))
    signature.sign
  }

  def verify_signature(key: Any, data: Any, signature: Any): Boolean = {
    val public_key: PublicKey = as_public_key(key)
    val signature_obj = Signature.getInstance(default_signature_algorithm, default_provider)
    signature_obj.initVerify(public_key)
    signature_obj.update(get_data_bytes(data))
    signature_obj.verify(get_data_bytes(signature))
  }

  def create_salt(): Int = {
    new Random().nextInt
  }

  def encrypt_password_string(password: Any, salt: Any, algorithm: String = default_encrypt_password_algorithm, n: Int = default_encrypt_password_n): String = {
    val message_digest = MessageDigest.getInstance(algorithm)
    message_digest.reset
    message_digest.update(get_data_bytes(salt))

    var data: Array[Byte] = get_data_bytes(password)
    for (i <- 0 to n) {
      message_digest.reset
      data = message_digest.digest(data)
    }
    Base64.encodeBase64String(data)
  }

}
