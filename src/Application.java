import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.Cipher.*;
import javax.crypto.spec.IvParameterSpec;

public class Application {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, BadPaddingException, IllegalBlockSizeException {

        String Message = "gotcha";
        System.out.printf("Unencrypted Message: %s\n", Message);

        System.out.printf("Bytes of OG Message %s\n", Arrays.toString(Message.getBytes()) );

        KeyGenerator k_gen = KeyGenerator.getInstance("AES");
        k_gen.init(128); // size of AES Key - 128
        SecretKey sKey = k_gen.generateKey();

        SecureRandom random = new SecureRandom(); // generates random vector
        byte[] init_vect = new byte[128/8]; // AES default block size = 128
        random.nextBytes(init_vect);
        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

        // Generate keyPairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); //size of RSA key - 2048
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate(); // returns PKCS#8 format
        PublicKey publicKey = pair.getPublic(); // returns X.509 format

        // contains sharedkey and init_vector
        byte[][] encryptedOut = Encryption.fullEncryption(sKey, init_vect, ivspec, privateKey, publicKey, Message);
        //encryptedOut[0] = bytes_sharedKey;
        //encryptedOut[1] = init_vec;
        //encryptedOut[2] = out_buffer;

        System.out.println("==========================================");

        byte[] final_message = Encryption.fullDecryption(publicKey, encryptedOut[0], encryptedOut[1],
                encryptedOut[2]);
        System.out.printf("Bytes of NEW Message %s\n", Arrays.toString(final_message));
        String message = new String(final_message);
        System.out.printf("Message: %s", message);
    }
}
