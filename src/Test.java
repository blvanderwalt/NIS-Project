
// --- Some Tests --- //

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;

public class Test {

    public static void main(String [] args){

        // --- Test Compression & Decompression --- //
        System.out.println("// --- Compression & Decompression --- //");
        String test = "Testing Compession and Decompression functions. \nHere we go!";
        System.out.println("original: " + test);
        byte [] zipTest = Encryption.compress(test);
        System.out.println("zipped: " + Arrays.toString(zipTest));
        
        String unzipTest = Encryption.decompress(zipTest);
        System.out.println("unzipped: " + unzipTest);

        System.out.println("================================================");
        // --- Test Encryption and Decryption --- //
        try{
            System.out.println("// --- Test Encryption and Decryption --- //");
            String Message = "This is a secret message\nWho do you think sent it?";
            System.out.printf("Unencrypted Message: %s\n", Message);
            System.out.printf("Bytes of Original  Message %s\n", Arrays.toString(Message.getBytes()) );

            KeyGenerator k_gen = KeyGenerator.getInstance("AES");
            k_gen.init(128);
            SecretKey sKey = k_gen.generateKey();

            SecureRandom random = new SecureRandom();
            byte[] init_vect = new byte[128/8];
            random.nextBytes(init_vect);
            IvParameterSpec ivspec = new IvParameterSpec(init_vect);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); //size of RSA key - 2048
            KeyPair pair = keyGen.generateKeyPair();

            PrivateKey privateKey = pair.getPrivate(); // returns PKCS#8 format
            PublicKey publicKey = pair.getPublic(); // returns X.509 format

            byte[] encryptedOut = Encryption.encrypt(sKey, init_vect, publicKey, Message.getBytes());
            System.out.println("= = = = = = = = = = = = = = = = = = =");


            byte[] final_message = Encryption.decrypt(privateKey, encryptedOut);
            System.out.printf("Bytes of NEW Message %s\n", Arrays.toString(final_message));

            String message = new String(final_message);
            System.out.printf("Message: %s\n", message);
            System.out.println("================================================");
        }catch(Exception ex){
            ex.printStackTrace();
        }

    }
}