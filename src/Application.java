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

        //playEncryption(false);

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

        String Message = "Hackerman has arrived\nHacker is here\nYeaaaah baby";

        byte[] encryptedsharedKey = Encryption.fullEncryption(sKey, init_vect, ivspec, privateKey, publicKey, Message);

        /* To Do:
            practice AES encryption
            encrypt AES key with RSA
            - Follow up with PGP framework
         */

        Encryption en = new Encryption();
        String encryptedM = en.encrypt("r", puKey64);

        System.out.println("==========================================");

        // Issue is that data is too long
        // Either break up message or do something else? Hash or encrypting  wrong thing
        String decryptedM = en.decrypt(encryptedM, prKey64);

        System.out.println("Finished for today Hackerman");
        String[] final_message = Encryption.fullDecryption(publicKey, encryptedsharedKey, init_vect);

        System.out.printf("The decrypted message: \n%s", String.join("\n", final_message));
    }

//    private static void playEncryption(boolean b) throws NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, CertificateException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
//        if (!b) return;
//
//        System.out.println("Encrypting the text inside text.txt with RSA");
//        System.out.println("encrypted stuff goes in test_output.txt");
//        System.out.println("decrypted test_output.txt goes in verfication.txt");
//
//        // Generate keyPairs
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//        keyGen.initialize(2048);
//        KeyPair pair = keyGen.generateKeyPair();
//
//        PrivateKey privateKey = pair.getPrivate(); // returns PKCS#8 format
//        PublicKey publicKey = pair.getPublic(); // returns X.509 format
//
//        boolean writeToFiles = false;
//        if (writeToFiles){
//            // write private key file
//            try (FileOutputStream out = new FileOutputStream("private_key" + ".key")) {
//                out.write(privateKey.getEncoded());
//                out.flush();
//            }
//            // Read private key file back
//            byte[] bytesPR = Files.readAllBytes(Paths.get("private_key.key"));
//            PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(bytesPR);
//            KeyFactory kfp = KeyFactory.getInstance("RSA");
//            PrivateKey pvt = kfp.generatePrivate(pks);
//
//            // write public key file
//            try (FileOutputStream out = new FileOutputStream("public_keys" + ".pub")) {
//                out.write(publicKey.getEncoded());
//                out.flush();
//            }
//            // Read public key file back
//            byte[] bytesPU = Files.readAllBytes(Paths.get("public_keys.pub"));
//            X509EncodedKeySpec xks = new X509EncodedKeySpec(bytesPU);
//            KeyFactory kfx = KeyFactory.getInstance("RSA");
//            PublicKey pub = kfx.generatePublic(xks);
//        }
//
//        /*  Tested:
//                privateKey == pvt; publicKey == pub
//         */
//
//        // Convert to Base64 for easier transfer
//        String publicKey64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
//        String privateKey64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
//
//        String encryptedM = Encryption.encryptRSA("r", publicKey64, privateKey64);
//        // Issue is that data is too long
//        // Either break up message or do something else? Hash or encrypting  wrong thing
//        String decryptedM = Encryption.decryptRSA(encryptedM, publicKey64, privateKey64);
//
//        System.out.println("Finished RSA Hackerman - check files, now AES\n");
//        System.out.println("Encrypting the text inside AES.txt with AES");
//        System.out.println("encrypted stuff goes in AES_output.txt");
//        System.out.println("decrypted test_output.txt goes in AES_verification.txt");
//
//        /* To Do:
//            encrypt AES key with RSA
//            - Follow up with PGP framework
//         */
//
//        KeyGenerator k_gen = KeyGenerator.getInstance("AES");
//        k_gen.init(128);
//        SecretKey sKey = k_gen.generateKey();
//
//        SecureRandom random = new SecureRandom();
//        byte[] init_vect = new byte[128/8]; // AES default block size = 128
//        random.nextBytes(init_vect);
//        IvParameterSpec ivspec = new IvParameterSpec(init_vect);
//
//        //Write this key to a file
////        try (FileOutputStream out = new FileOutputStream("AES_key.enc")) {
////            byte[] keyb = sKey.getEncoded();
////            out.write(keyb);
////        }
//
//        //Or load key from file
////        byte[] keyb = Files.readAllBytes(Paths.get("AES_key.enc"));
////        SecretKeySpec skey = new SecretKeySpec(keyb, "AES");
//
//        String enM = Encryption.encryptAES("r", sKey, ivspec);
//        // Issue is that data is too long
//        // Either break up message or do something else? Hash or encrypting  wrong thing
//        String deM = Encryption.decryptAES("r", sKey, ivspec);
//
//        System.out.println("Finished AES, go check files");
//    }
}
