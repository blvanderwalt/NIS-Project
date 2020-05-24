// NIS 2020
// Authentication Class
// -- Performs the authentication service between the clients and server
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.util.Arrays;

public class Message{
    //fields (public for now) !!![final? immutable]!!!
    //--> header
    protected class SessionKeyComponent{
        String recipientPublicKey;
        String sessionKey; //idk if we use this
    }
    protected class Signature{
        long timestamp;
        String senderPublicKey;
        byte[] messageDigest;
        String signedMD;
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
    public Message(String plaintext, String senderPublicKey, String recipientPublicKey){
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
    public Message(String dcMessage){
        this.construct(fullMessage.getBytes());
    }
    //byte[] constructor
    public Message(byte[] fullMessage){
        this.construct(fullMessage);
    }

    private void construct(byte[] fullMessage){
        //TODO: assigning
    }

    /**
     * Sets session key and sets symmetric key encryption flag to true
     * @params sessionKey   session key to be used for encryption/decrytion
     */
    void setSessionKey(String sessionKey){
        this.sessionKeyComponent.sessionKey = sessionKey;
        symmetric = true;
    }
    //toByteArray
    //for each thing, last 2bytes says length
    //length (short si to byte[] arr): arr[0] = (byte)(si >> 8); arr[1] = (byte)si;
    /**
     * Returns the compressed concatenated payload and signature components of
     * the pgp message as a byte array
     */
    byte[] toByteArray(){
        if(!signed) System.err.println("Message is not signed");
        if(symmetric) {}//?
        int SIZE = 0;
        //TODO: signature|payload > compress

        return null; //[--temp]
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
