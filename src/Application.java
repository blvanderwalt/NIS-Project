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
import javax.crypto.Cipher.*;

public class Application {
    public static void main(String[] args) throws NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, CertificateException, NoSuchProviderException, InvalidKeySpecException {
        // Check we have enough space
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);

        // Generate keyPairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate(); // returns PKCS#8 format
        PublicKey publicKey = pair.getPublic(); // returns X.509 format

        boolean writeToFiles = false;
        if (writeToFiles){
            // write private key file
            try (FileOutputStream out = new FileOutputStream("private_key" + ".key")) {
                out.write(privateKey.getEncoded());
                out.flush();
            }
            // Read private key file back
            byte[] bytesPR = Files.readAllBytes(Paths.get("private_key.key"));
            PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(bytesPR);
            KeyFactory kfp = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kfp.generatePrivate(pks);

            // write public key file
            try (FileOutputStream out = new FileOutputStream("public_keys" + ".pub")) {
                out.write(publicKey.getEncoded());
                out.flush();
            }
            // Read public key file back
            byte[] bytesPU = Files.readAllBytes(Paths.get("public_keys.pub"));
            X509EncodedKeySpec xks = new X509EncodedKeySpec(bytesPU);
            KeyFactory kfx = KeyFactory.getInstance("RSA");
            PublicKey pub = kfx.generatePublic(xks);
        }

        // Why Base64? To Ease sharing of keys

        // getEncoded = byte[]
        String puKey64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println(puKey64);
        String prKey64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println(prKey64);

        /* To Do:
            practice AES encryption
            encrypt AES key with RSA
            - Follow up with PGP framework
         */

        Encryption en = new Encryption();
        String encryptedM = en.encrypt("r", puKey64, prKey64);

        System.out.println("==========================================");

        // Issue is that data is too long
        // Either break up message or do something else? Hash or encrypting  wrong thing
        String decryptedM = en.decrypt(encryptedM, puKey64, prKey64);

        System.out.println("Finished for today Hackerman");

    }
}
