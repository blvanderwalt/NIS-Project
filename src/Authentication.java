// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.*;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.cert.X509CertificateHolder;
import java.util.Date;

public class Authentication {
    private static int MESSAGE_DIGEST_SIZE = 256; //bits
    private static int PUBLIC_KEY_SIZE = 3136; //bits

    /**
     * signs the input plaintext, using the provided private key
     * @params  privateKey  the private key used for the signature
     * @params  plaintext   the message to be signed
     * @return  authentication signature using the private key
     */
    public static String sign(String privateKey, String plaintext){
        String msghash = new String(hash(plaintext));
        String sig = Encryption.encrypt(msghash, privateKey);
        /*debug --*/ System.out.printf("(plaintext) %s -> (signature) %s%n", plaintext,sig);
        return sig;
    }

    /**
     * digitally signs the input message
     * @param  privateKey  the private key used for the signature
     * @param  msg         the instance of the Message class to be signed
     * @return  authentication signature using the private key
     */
    public static void sign(final PrivateKey privateKey, Message msg){
        byte[] msghash = hash(msg.payload.plaintext);
        byte[] sig = Encryption.encrypt(msghash, privateKey);

        /*debug --*/ System.out.printf("(plaintext) %s -> (signature) %s%n", msg.payload.plaintext,sig);
        msg.signature.messageDigest = msghash;
        msg.signature.signedMD = sig;
        msg.signature.timestamp = System.currentTimeMillis();
        msg.signed = true;
    }

    public static boolean authenticateSender(X509CertificateHolder certificate){
        //check expiry date
        boolean notExpired = certificate.isValidOn(new Date(System.currentTimeMillis()));
        //make sure it's not on revoke list
        boolean notRevoked = true; //assumption since using fake CA
        /*debug --*/ System.out.printf("Sender cerficate expired: %b%n",!notExpired);
        /*debug --*/ System.out.printf("Sender certificate on revocation list: %b%n", !notRevoked);
        /*debug --*/ System.out.printf("Authentication result: %b%n", notExpired&&notRevoked);
        return (notExpired&&notRevoked);
    }

    /**
     * Assumes the sender has been autheticated and authenticates only the
     * validity of the input message.
     * @param msg  the instance of the Message class to be authenticated
     * @return  returns true if message is authentic, false otherwise
     */
    public static boolean authenticateMessage(Message msg) {
        String plaintext = msg.payload.plaintext;
        String oghash = new String(msg.signature.messageDigest);
        String myhash = new String(hash(plaintext));
        /*debug --*/ System.out.printf("(original hash) %s == (calculated hash) %s%n",oghash,myhash);
        /*debug --*/ System.out.printf("Authentication result: %b%n", oghash.equals(myhash));
        return oghash.equals(myhash);
    }

    /**
     * creates a 256 bit message digest ("hash") of plaintext using SHA-256
     * algorithm.
     * @param  plaintext   plaintext to be hashed
     * @return  returns a 256 bit hash of the plain text provided
     * @exception NoSuchAlgorithmException on hashing algorithm
     */
    public static byte[] hash(final String plaintext){
        // Using SHA-256 algorithm to generate a 256 bit hash
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bHash = md.digest(plaintext.getBytes(StandardCharsets.UTF_8));
            String sHash = new String(bHash);
            /*debug --*/ System.out.printf("(plaintext) %s -> (hash) %s%n",plaintext,sHash);
            /*debug --*/ System.out.printf("Number of bits in hash: %d%n",bHash.length*8);
            return bHash;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String extractPlaintext(final String message){
        // last 2 bytes says plaintext message size
        byte[] msg = message.getBytes();
        int fullsize = msg.length;
        short size = (short) (msg[fullsize-2]<<8 | msg[fullsize-1] & 0xFF);
        /*debug --*/ System.out.printf("Full message length: %d%n",fullsize);
        /*debug --*/ System.out.printf("Plaintext message length: %d%n",size);
        String plaintext = message.substring(message.length()-2 - size, message.length()-2);
        /*debug --*/ System.out.printf("Extracted plaintext: %s%n",plaintext);
        return plaintext;
    }

    public static String extractSignature(final String message){
        // as above
        byte[] msg = message.getBytes();
        int fullsize = msg.length;
        short size = (short) (msg[fullsize-2]<<8 | msg[fullsize-1] & 0xFF);
        /*debug --*/ System.out.printf("Full message length: %d%n",fullsize);
        /*debug --*/ System.out.printf("Plaintext message length: %d%n",size);
        String signature = message.substring(0, message.length()-2 - size);
        /*debug --*/ System.out.printf("Extracted signature: %s%n",signature);
        return signature;
    }
}
