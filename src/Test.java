
// --- Some Tests --- //

import java.util.Arrays;

public class Test {

    public static void main(String [] args){

        // --- Test Compression & Decompression --- //
        System.out.println("// --- Compression & Decompression --- //");
        String test = "Testing Compession and Decompression functions. \nHere we go!";
        System.out.println("original: " + test);
        byte [] zipTest = Encryption.compress(test);
        System.out.println("zipped: " + zipTest);
        
        String unzipTest = Encryption.decompress(zipTest);
        System.out.println("unzipped: " + unzipTest);
        System.out.println();
        
        // --- Next Test --- //
    }
}