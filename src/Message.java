// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.util.Arrays;
import java.security.*;
import java.security.spec.X509EncodedKeySpec; 
import java.security.spec.InvalidKeySpecException;

public class Message{
    //fields (public for now) !!![final? immutable]!!!
    //--> header
    protected class SessionKeyComponent{
        PublicKey recipientPublicKey;
        byte[] sessionKey; //idk if we use this
    }
    protected class Signature{
        long timestamp;
        PublicKey senderPublicKey;
        byte[] messageDigest;
        byte[] signedMD;
    }
    //--> payload
    protected class Payload{
        String filename; //not really using this
        long timestamp;
        String plaintext;
    }

    SessionKeyComponent sessionKeyComponent;
    Signature signature;
    Payload payload;
    boolean signed = false;
    boolean symmetric = false;
    //message byte sizes: 392 + g[392] + 8 + 392 + 2 + g[32] + 1 + 8 + [x+2]

    //no default constructor

    /**
     * non default constructor
     * @params plaintext        payload plaintext of pgp message
     * @params senderPublicKey  public key of the sending party
     */
    public Message(String plaintext, PublicKey senderPublicKey, PublicKey recipientPublicKey){
        sessionKeyComponent = new SessionKeyComponent();
        signature = new Signature();
        payload = new Payload();
        this.payload.plaintext = plaintext;
        this.payload.timestamp = System.currentTimeMillis();
        this.signature.senderPublicKey = senderPublicKey;
        this.sessionKeyComponent.recipientPublicKey = recipientPublicKey;
    }
    /**
     * string constructor
     * @params fullMessage string containing a decompressed signature and payload
     */
    public Message(String fullMessage) throws InvalidKeySpecException, NoSuchAlgorithmException {
        sessionKeyComponent = new SessionKeyComponent();
        signature = new Signature();
        payload = new Payload();
        this.construct(fullMessage.getBytes());
    }
    //byte[] constructor
    public Message(byte[] fullMessage) throws InvalidKeySpecException, NoSuchAlgorithmException {
        sessionKeyComponent = new SessionKeyComponent();
        signature = new Signature();
        payload = new Payload();
        this.construct(fullMessage);
    }

    private void construct(byte[] fullMessage) throws InvalidKeySpecException, NoSuchAlgorithmException{
        int index = fullMessage.length - 2;
        byte[] sba = new byte[2];
        System.arraycopy(fullMessage,index,sba,0,2);
        short si = (short) (sba[0]<<8 | sba[1] & 0xFF);

        index -= si;
        byte[] plaintextBytes = new byte[(int)si];
        System.arraycopy(fullMessage,index,plaintextBytes,0,si);
        payload.plaintext = new String(plaintextBytes);
        signature.messageDigest = Authentication.hash(payload.plaintext);

        index -= 8;
        byte[] lba = new byte[8];
        System.arraycopy(fullMessage,index,lba,0,8);
        payload.timestamp = bytesToLong(lba);

        index -= 2;
        System.arraycopy(fullMessage,index,sba,0,2);
        si = (short) (sba[0]<<8 | sba[1] & 0xFF);

        index -= si;
        signature.signedMD = new byte[(int)si];
        System.arraycopy(fullMessage,index,signature.signedMD,0,si);

        index -= 394;
        byte[] keyBytes = new byte[392];
        System.arraycopy(fullMessage,index,keyBytes,0,392);
        signature.senderPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

        index -= 8;
        assert index==0;
        System.arraycopy(fullMessage,0,lba,0,8);
        signature.timestamp = bytesToLong(lba);

        signed = (signature.signedMD.length > 0)
                  && !Arrays.equals(signature.signedMD, new byte[si]);
    }

    /**
     * Sets session key and sets symmetric key encryption flag to true
     * @params sessionKey   session key to be used for encryption/decrytion
     */
    void setSessionKey(byte[] sessionKey){
        this.sessionKeyComponent.sessionKey = sessionKey;
        symmetric = true;
    }

    //for each thing, last 2bytes says length
    //length (short si to byte[] arr): arr[0] = (byte)(si >> 8); arr[1] = (byte)si;
    /**
     * Returns the compressed concatenated payload and signature components of
     * the pgp message as a byte array
     */
    byte[] toByteArray(){
        if(!signed) System.err.println("Message is not signed");
        if(symmetric) {}//?

        //signature|payload > compress
        byte[] pl = payload.plaintext.getBytes();

        short si = (short)signature.signedMD.length;
        byte[] mdl = new byte[]{(byte)(si >> 8), (byte)si};
        si = (short)pl.length;
        byte[] pll = new byte[]{(byte)(si >> 8), (byte)si};

        int len = 8+392+2+signature.signedMD.length+2+0+8+pl.length+2;
        byte[] output = new byte[len];

        System.arraycopy(longToBytes(signature.timestamp),0,output,0,8);
        System.arraycopy(signature.senderPublicKey.getEncoded(),0,output,8,392);
        System.arraycopy(signature.messageDigest,0,output,400,2);
        System.arraycopy(signature.signedMD,0,output,402,signature.signedMD.length);
        System.arraycopy(mdl,0,output,402+signature.signedMD.length,2);
        System.arraycopy(longToBytes(payload.timestamp),0,output,404+signature.signedMD.length,8);
        System.arraycopy(pl,0,output,412+signature.signedMD.length,pl.length);
        System.arraycopy(pll,0,output,412+signature.signedMD.length+pl.length,2);

        byte[] cp_output = Encryption.compress(new String(output));

        return cp_output;
    }
    //toString

    private byte[] longToBytes(long li){
        byte[] ba = new byte[8];
        for(int i = 7; i >= 0; i--){
            ba[i] = (byte)(li & 0xFF);
            li >>= 8;
        }
        return ba;
    }

    private long bytesToLong(final byte[] ba){
        long li = 0;
        for(int i = 0; i < 8; i++){
            li = (long)(li << 8 | ba[i] & 0xFF);
        }
        return li;
    }
}
