
// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Authentication {

    public static String sign(String privateKey, String plaintext){
        String msghash = hash(plaintext);
        //sig = encrypt(privateKey, msghash)
        //return sig
        return null; //[--temp]
    }

    public static boolean authenticate(String publicKey, String message) {
        String dcmsg = Encryption.decompress(message); //dcmsg = plaintext | sig
        /*debug --*/ System.out.printf("Decompressed message -> %s%n",dcmsg);
        //sig = extractSignature(dcmsg)
        //plaintext = extractPlaintext(dcmsg)
        String oghash = Encryption.decrypt(sig, publicKey);
        //String myhash = hash(plaintext);
        //return oghash.compare(myhash);
        // /*debug --*/ System.out.printf("(original hash) %s == (calculated hash) %s%n",oghash,myhash);
        // /*debug --*/ System.out.printf("Authentication result: %b%n", oghash.compare(myhash));
        return true; //[--temp]
    }

    public static String hash(String plaintext){
        // Using SHA-256 algorithm to generate a 256 bit hash
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bHash = md.digest(plaintext.getBytes());
            String sHash = new String(bHash);
            /*debug --*/ System.out.printf("(plaintext) %s -> (hash) %s%n",plaintext,sHash);
            return sHash;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

}
