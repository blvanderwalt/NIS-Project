
// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

public class Authentication {

    public String sign(String privateKey, String plaintext){
        //msghash = hash(plaintext)
        //sig = encrypt(privateKey, msghash)
        //return sig
    }

    public boolean authenticate(String publicKey, String message) {
        //dcmsg = decompress(message) //dcmsg = sig | plaintext
        //sig = extractSignature(dcmsg)
        //plaintext = extractPlaintext(dcmsg)
        //oghash = decrypt(publicKey, sig)
        //myhash = hash(plaintext)
        //return compare(oghash, myhash)
    }

}
