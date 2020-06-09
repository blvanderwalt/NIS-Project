
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

//for encryption/decryption
import java.security.*;
import java.util.ArrayList;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//for (de)compression
import java.util.Arrays;
import java.util.zip.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Encryption {
    // --- Encryptionion and Decryption --- //

    /**
     * Take in the message hash and private key
     * @return signature in a byte[]
    */
    public static byte[] extractSig(byte[] msghash, PrivateKey privateKey) {
        byte[] signed_hash = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            signed_hash = cipher.doFinal(msghash);
        }catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            e.printStackTrace();
        }

        return signed_hash;
    }

    /**
     * Take in the message hash and public key
     * @return signature in a byte[]
     */
    public static byte[] extractSig(byte[] msghash, PublicKey publicKey) {
        byte[] signed_hash = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            signed_hash = cipher.doFinal(msghash);
        }catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            e.printStackTrace();
        }

        return signed_hash;
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] init_vect,
                                 PublicKey publicKey, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException{

        //SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

       /**
        * Used for creating secret key but in this case we have that already
        *
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] bytes_sharedKey = cipher.doFinal(secretKey.getEncoded());
        SecretKey sKey = new SecretKeySpec(bytes_sharedKey, 0, bytes_sharedKey.length, "AES");
        */
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();

        // Encrypt File content using AES key
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherAES.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        byte[] AES_encryptedPayload = cipherAES.doFinal(message);

        byteOut.write(AES_encryptedPayload);

//        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] bytes_sharedKey = cipherRSA.doFinal(secretKey.getEncoded());



        ArrayList<byte[]> out = new ArrayList<byte[]>();

//        byte[] input_buffer = new byte[1024];
////        int input_len = 0;
////        ByteArrayInputStream in = new ByteArrayInputStream(message);
////
////        // in.read reads input_buffer.length # of bytes; returned as int
////        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
////            do {
////                byte[] out_buffer = ci.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
////                if (out_buffer != null) {
////                    out.add(out_buffer);
////                }
////            } while ((input_len = in.read(input_buffer)) != -1);
////        }
////        byte[] AES_encryptedPayload = ci.doFinal();

        out.add(AES_encryptedPayload);



        //TODO: Concatenate AES_encryptedPayload ++ bytes_sharedKey
        //byte[] out = AES_encryptedPayload ++ bytes_sharedKey;
        return AES_encryptedPayload;
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] init_vect, PrivateKey privateKey, byte[] message) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        //SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);
        //byte[] shared_key = cipherRSA.doFinal(message.getBytes()); //retrieves secret AES key

        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //SecretKeySpec secret_key = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipherAES.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        System.out.println(message.length);
        byte[] out_buffer = cipherAES.doFinal(message);


//        ArrayList<byte[]> out = new ArrayList<byte[]>();
//
//        byte[] input_buffer = new byte[1024];
//        input_buffer = message.getBytes();
//
//        int input_len = 0;
//        ByteArrayInputStream in = new ByteArrayInputStream(input_buffer);
//
//        // in.read reads input_buffer.length # of bytes; returned as int
//        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
//            do {
//                byte[] out_buffer = ci.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
//                if (out_buffer != null) {
//                    out.add(out_buffer);
//                }
//            } while ((input_len = in.read(input_buffer)) != -1);
//        }
//        byte[] out_buffer = ci.doFinal();
//
//        out.add(out_buffer);


        return out_buffer;
    }

    public static byte[] getSharedKey(PrivateKey pvtKey, byte[] encryptedMessage) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, pvtKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(encryptedMessage);
        byte[] encryptedSharedKey = new byte[256]; // Is this fixed??
        bIn.read(encryptedSharedKey);


        byte[] shared_key = cipherRSA.doFinal(encryptedSharedKey); //retrieves secret AES key
        return shared_key;
    }

    public static byte[] getIV(PrivateKey pvtKey, byte[] encryptedMessage) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, pvtKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(encryptedMessage);
        bIn.readNBytes(256); // skip the shared_key

        byte[] init_v = new byte[16]; // get IV bytes
        bIn.read(init_v);


        byte[] init_vector = cipherRSA.doFinal(init_v); //retrieves secret AES key
        return init_vector;
    }


    /**
     * Process: RSA encryption has a very low limit for data that can be encrypted. therefore to encrypt larger sets of
     * data we use symmetric encryption, AES, for encryption - THEN we encrypt the RSA for encrypting the AES key itself
     *
     * Takes a whole bunch of variables used to encryption AND the secret message
     * created a file for the encryptedAES key and plaintext.txt for the secret message
     *
     * @return the encrypted sharedKey byte array.
     */
    public static byte[][] fullEncryption(byte[] shared_key, byte[] init_vect, PublicKey publicKey, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        IvParameterSpec ivspec = new IvParameterSpec(init_vect);
        SecretKey originalKey = new SecretKeySpec(shared_key, 0, shared_key.length, "AES");


        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes_sharedKey = cipher.doFinal(shared_key);

        System.out.println("Unencrypted: " + Arrays.toString(shared_key));

        // Encrypt File content using AES key
        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, originalKey, ivspec);

//        ArrayList<byte[]> out = new ArrayList<byte[]>();
//
//        byte[] input_buffer = new byte[1024];
//        int input_len = 0;
//        ByteArrayInputStream in = new ByteArrayInputStream(message.getBytes());
//        //System.out.println(in.available()); //How many bytes in the InputStream
//
//        // in.read reads input_buffer.length # of bytes; returned as int
//        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
//            do {
//                System.out.println(input_len);
//                byte[] out_buffer = cipher.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
//                if (out_buffer != null) {
//                    out.add(out_buffer);
//                    System.out.println(Arrays.toString(out_buffer));
//                }
//            } while ((input_len = in.read(input_buffer)) != -1);
//        }

        byte[] out_buffer = ci.doFinal(message);
        //System.out.printf("Out buffer: %s\n", Arrays.toString(out_buffer));

        //out.add(out_buffer);

        byte[][] output = new byte[3][];
        output[0] = bytes_sharedKey;
        output[1] = init_vect;
        output[2] = out_buffer;

        System.out.printf("Length of sharedKey: %d\n", bytes_sharedKey.length);
        System.out.printf("Length of init_vec: %d\n", init_vect.length);
        System.out.printf("Length of out_buffer: %d\n", out_buffer.length);


//        byte[] d = new byte[256 + 16 + 256];
//        System.arraycopy(bytes_sharedKey, 0, d, 0, 256);
//        System.arraycopy(init_vect, 0, d, 256, 16);
//        System.arraycopy(out_buffer, 0, d, 256+16, 16);


        return output;
    }

    public static byte[] fullDecryption(PrivateKey pvtlicKey, byte[] encryptedsharedKey, byte[] init_vect,
                                        byte[] msg) throws IOException,
            NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

//        ByteArrayInputStream bIn = new ByteArrayInputStream(encryptedBlob);
//
//        byte[] encryptedsharedKey = bIn.readNBytes(256);
//        byte[] init_vect = bIn.readNBytes(16);
//        byte[] msg = bIn.readNBytes(256);



        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, pvtlicKey);
        byte[] shared_key = cipher.doFinal(encryptedsharedKey); //retrieves secret AES key

        System.out.println("Unencrypted" + Arrays.toString(shared_key));
        //System.out.printf("Out buffer: %s\n", Arrays.toString(msg));

        SecretKey secret_key = new SecretKeySpec(shared_key, "AES");

        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.DECRYPT_MODE, secret_key, ivspec);

        byte[] out_buffer = ci.doFinal(msg);


//        ArrayList<byte[]> out = new ArrayList<byte[]>();
//
//        byte[] input_buffer = new byte[1024];
//        input_buffer = msg;
//        int input_len = 0;
//        ByteArrayInputStream in = new ByteArrayInputStream(input_buffer);
//
//        // in.read reads input_buffer.length # of bytes; returned as int
//        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
//            do {
//                byte[] out_buffer = cipher.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
//                if (out_buffer != null) {
//                    out.add(out_buffer);
//                }
//            } while ((input_len = in.read(input_buffer)) != -1);
//        }
//        byte[] out_buffer = cipher.doFinal();

        return out_buffer;
    }

    // --- Compression and Decompression --- //

    // --- Compression --- //
    // Compresses String message into a byte array with ZIP
    public static byte [] compress (String message) {
        try {
            ByteArrayOutputStream byteArrOut = new ByteArrayOutputStream(message.length());
            GZIPOutputStream gzip = new GZIPOutputStream(byteArrOut);
            gzip.write(message.getBytes(StandardCharsets.UTF_8));
            gzip.close();
            byte[] compressed = byteArrOut.toByteArray();
            byteArrOut.close();
            return compressed;
        }
        catch (IOException e) {
            throw new RuntimeException ("Failed to zip message", e);
        }
    }

    // --- Decompression --- //
    // Decompresses the byte array into a string message
    public static String decompress (byte [] compressage) {
        try {
            ByteArrayInputStream byteArrIn = new ByteArrayInputStream(compressage);
            GZIPInputStream gzip = new GZIPInputStream(byteArrIn);
            InputStreamReader inStreamRead = new InputStreamReader(gzip, StandardCharsets.UTF_8);
            BufferedReader buffReader = new BufferedReader(inStreamRead);

            StringBuilder output = new StringBuilder();
            String line;
            int i = 0;
            while((line = buffReader.readLine()) != null){
                if (i > 0){
                    output.append("\n");
                }
                output.append(line);
                i++;
            }
            return output.toString();
        }
        catch (IOException e) {
            throw new RuntimeException ("Failed to unzip message", e);
        }
    }



}
