
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

class Signer implements ContentSigner{
     AlgorithmIdentifier ai;
     byte [] key;
     java.io.ByteArrayOutputStream os;

     public Signer(AlgorithmIdentifier ai, byte[] key){
         this.ai = ai;
         this.key = key;
         this.os = new java.io.ByteArrayOutputStream();
     }

     public AlgorithmIdentifier getAlgorithmIdentifier(){
         return ai;
     }
     
     public java.io.OutputStream getOutputStream(){
         return os;
     }
     
     public byte [] getSignature(){
         return Authentication.hash(os.toString());
     }
}
