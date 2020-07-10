import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil {

  private void generatePublicAndPrivateKey() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      savePublicKeys(keyPair.getPublic().getEncoded());
      savePrivateKeys(keyPair.getPrivate().getEncoded());
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  private PublicKey retrievePublicKey() {
    try {
      byte[] publicKeyBytes = Files.readAllBytes(Paths.get("/home/basanta/Work/RSADemo/keys/PublicKey/public" + ".pub"));
      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePublic(x509EncodedKeySpec);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  private PrivateKey retrievePrivateKey() {
    try {
      byte[] privateKeyBytes = Files.readAllBytes(Paths.get("/home/basanta/Work/RSADemo/keys/PrivateKey/private" + ".key"));
      PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  public byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
    byte[] cipherText = null;
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      cipherText = cipher.doFinal(plaintext);
      System.out.println("Cipher from public key : " + new String(cipherText, "UTF-8"));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    return cipherText;
  }


  public byte[] decrypt(PrivateKey privateKey, byte[] cipherText) {
    byte[] plainText = null;
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      plainText = cipher.doFinal(cipherText);
      System.out.println("Recovered text from private key : " + new String(plainText, "UTF-8"));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    return plainText;
  }

  private void savePublicKeys(byte[] publicKey) {
    try (FileOutputStream out = new FileOutputStream("/home/Work/RSADemo/keys/PublicKey/public" + ".pub")) {
      out.write(publicKey);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void savePrivateKeys(byte[] privateKey) {
    try (FileOutputStream out = new FileOutputStream("/home/Work/RSADemo/keys/PrivateKey/private" + ".key")) {
      out.write(privateKey);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void main(String[] args) throws UnsupportedEncodingException {
    RSAUtil rsaUtil = new RSAUtil();
    rsaUtil.generatePublicAndPrivateKey();
    String textToEncrypt = "Luke Skywalker";
    byte[] cipherText = rsaUtil.encrypt(rsaUtil.retrievePublicKey(), textToEncrypt.getBytes("UTF8"));
    rsaUtil.decrypt(rsaUtil.retrievePrivateKey(), cipherText);
  }
}
