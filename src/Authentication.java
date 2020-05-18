// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class Authentication {
    private static int MESSAGE_DIGEST_SIZE = 256;

    /**
     * signs the input plaintext, using the provided private key
     * @params  privateKey  the private key used for the signature
     * @params  plaintext   the message to be signed
     * @return  authentication signature using the private key
     */
    public static String sign(String privateKey, String plaintext){
        String msghash = hash(plaintext);
        String sig = Encryption.encrypt(msghash, privateKey);
        /*debug --*/ System.out.printf("(plaintext) %s -> (signature) %s%n", plaintext,sig);
        return sig;
    }

    /**
     * authenticates the validity of the input message
     * @params  publicKey public key of the sender
     * @params  message   byte array of the message to be authenticated
     * @return  returns true if message is authentic, false otherwise
     */
    public static boolean authenticate(String publicKey, byte [] message) {
        /*debug --*/ System.out.printf("Compressed message: %s%n",new String(message));
        String dcmsg = Encryption.decompress(message); //dcmsg = plaintext | sig
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
            byte[] bHash = md.digest(plaintext.getBytes(StandardCharsets.UTF_8));
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
        // we need to add a field in the header that says plaintext message size
        String plaintext = "";//message.substring(0, ??);
        /*debug --*/ System.out.printf("Extracted plaintext: %s%n",plaintext);
        return plaintext;
    }

    public static String extractSignature(String message){
        // as above
        String signature = "";//message.substring(??);
        /*debug --*/ System.out.printf("Extracted signature: %s%n",signature);
        return signature;
    }
}
