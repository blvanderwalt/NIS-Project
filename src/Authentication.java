
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
        //dcmsg = decompress(message) //dcmsg = plaintext | sig
        //sig = extractSignature(dcmsg)
        //plaintext = extractPlaintext(dcmsg)
        //oghash = decrypt(publicKey, sig)
        //myhash = hash(plaintext)
        //return compare(oghash, myhash)
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
