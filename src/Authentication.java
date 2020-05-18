
// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Authentication {
    private static int SIGNATURE_SIZE = 256;

    /**
     * signs the input plaintext, using the provided private key
     * @params  privateKey  the private key used for the signature
     * @params  plaintext   the message to be signed
     * @return  authentication signature using the private key
     */
    public static String sign(String privateKey, String plaintext){
        String msghash = hash(plaintext);
        String sig = Encryption.encrypt(privateKey, msghash);
        /*debug --*/ System.out.printf("plaintext: %s -> signature %s%n", plaintext,sig);
        return sig;
    }

    /**
     * authenticates the validity of the input message
     * @params  publicKey public key of the sender
     * @params  message   message to be authenticated
     * @return  returns true if message is authentic, false otherwise
     */
    public static boolean authenticate(String publicKey, String message) {
        byte [] msg = message.getBytes();
        /*debug --*/ System.out.printf("Compressed message: %s%n",message);
        String dcmsg = Encryption.decompress(msg); //dcmsg = plaintext | sig
        /*debug --*/ System.out.printf("Decompressed message -> %s%n",dcmsg);
        String sig = extractSignature(dcmsg);
        String plaintext = extractPlaintext(dcmsg);
        String oghash = Encryption.decrypt(sig, publicKey);
        String myhash = hash(plaintext);
        /*debug --*/ System.out.printf("(original hash) %s == (calculated hash) %s%n",oghash,myhash);
        /*debug --*/ System.out.printf("Authentication result: %b%n", oghash.equals(myhash));
        return oghash.equals(myhash);
    }

    /**
     * creates a 256 bit message digest ("hash") of plaintext using SHA-256
     * algorithm.
     * @params  plaintext   plaintext to be hashed
     * @return  returns a 256 bit hash of the plain text provided
     * @exception NoSuchAlgorithmException on hashing algorithm
     */
    public static String hash(String plaintext){
        // Using SHA-256 algorithm to generate a 256 bit hash
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bHash = md.digest(plaintext.getBytes());
            String sHash = new String(bHash);
            /*debug --*/ System.out.printf("(plaintext) %s -> (hash) %s%n",plaintext,sHash);
            /*debug --*/ System.out.printf("Number of bits in hash: %d%n",bHash.length*8);
            return sHash;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String extractPlaintext(String message){
        // everything minus the last 256 bits
        return ""; //[--temp]
    }

    public static String extractSignature(String message){
        // the last 256 bits
        return ""; //[--temp]
    }
}
