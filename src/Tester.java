import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import java.security.*;
import java.util.Base64;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

public class Tester{
    public static void main(String[] args) {
        Authentication.hash("hello world");

        try{
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate(); // returns PKCS#8 format
            PublicKey publicKey = pair.getPublic(); // returns X.509 format
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
                new Signer(subjectPubKeyInfo.getAlgorithm(), publicKey.getEncoded())
            );

            Authentication.authenticateSender(cert);

            String Uk = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String Rk = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            System.out.printf("public key length: %d%n",Uk.getBytes().length * 8);

            // short si = 19; byte[] arr = new byte[2];
            // arr[0] = (byte)(si >> 8); arr[1] = (byte)si;
            // String sig = Authentication.sign(Uk,"a plaintext message");
            // String signed = sig+"a plaintext message"+new String(arr);
            // byte [] cmp = Encryption.compress(signed);
            // Authentication.authenticateMessage(Rk,cmp);

            Message message = new Message("a plaintext message",Uk,Uk);
            Authentication.sign(Uk,message); //ask Ryan to make it work for a priv key too
            byte[] msgBytes = message.toByteArray();
            System.out.println("compressed: "+new String(msgBytes));
            String dcBytes = Encryption.decompress(msgBytes);
            System.out.println("decompressed: "+dcBytes);

            Message m2 = new Message(dcBytes);
            System.out.println("symmetric: "+m2.symmetric);
            Authentication.authenticateMessage(m2);
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }
}
