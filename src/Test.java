
// --- Some Tests --- //

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import java.math.BigInteger;
import java.util.GregorianCalendar;
import java.util.Locale;

public class Test {

    public static void main(String [] args){
        System.out.println("\n\n// --- Starting tests --- //\n");
        // --- Test Compression & Decompression --- //
        System.out.println("// --- Compression & Decompression --- //\n");
        String test = "Testing Compession and Decompression functions. \nHere we go!";
        System.out.println("original: " + test);
        byte [] zipTest = Encryption.compress(test);
        System.out.println("zipped: " + Arrays.toString(zipTest));
        
        String unzipTest = Encryption.decompress(zipTest);
        System.out.println("unzipped: " + unzipTest);

        System.out.println("================================================\n");
        // --- Test Encryption and Decryption --- //
        try{
            System.out.println("// --- Test Encryption and Decryption --- //\n");
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
            System.out.println("================================================\n");
            // --- Test Authentication --- //
            System.out.println("// --- Test Authentication --- //\n");
            System.out.println("...Authenticating Sender");
            SubjectPublicKeyInfo subjectPubKeyInfo = new SubjectPublicKeyInfo(
               new AlgorithmIdentifier(X509CertificateStructure.id_RSAES_OAEP),
               publicKey.getEncoded()
            );
            X509v3CertificateBuilder certBuild = new X509v3CertificateBuilder(
               new X500Name("CN=issuer"), //issuer
               new BigInteger("3874699348568"), //serial no
               new GregorianCalendar(2020,4,1).getTime(), //issue date
               new GregorianCalendar(2020,8,31).getTime(), //expiry date
               Locale.getDefault(), //date locale
               new X500Name("CN=subject"), //subject
               subjectPubKeyInfo //subjects public key info: algorithm and public key
           );
           X509CertificateHolder cert = certBuild.build(
               new OurSigner(subjectPubKeyInfo.getAlgorithm(), publicKey.getEncoded())
           );

           Authentication.authenticateSender(cert);
           System.out.println("= = = = = = = = = = = = = = = = = = =");
           
           System.out.println("...Authenticating Message");
           Message m2 = new Message("a plaintext message",publicKey,publicKey);
           Authentication.sign(privateKey,m2);
           Authentication.authenticateMessage(m2);
           System.out.println("================================================");
        }catch(Exception ex){
            ex.printStackTrace();
        }

    }
}
