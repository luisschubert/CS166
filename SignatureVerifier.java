import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Created by lschubert on 9/30/15.
 */
public class SignatureVerifier {
    public static void main(String[] args)throws Exception{
        //args0 is signedfile.
        //args1 is public key


        //byte[] for signature
        Path path = Paths.get(args[0]);
        byte[] b64Signature = Files.readAllBytes(path);
        byte[] signature = decodeFromB64(b64Signature);


        //byte[] for public key
        path = Paths.get(args[1]);
        byte[] b64publicKey = Files.readAllBytes(path);
        byte[] pk = decodeFromB64(b64publicKey);


        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pk));

        Signature s = Signature.getInstance("SHA256withRSA");
        s.update(signature);
        s.initVerify(publicKey);
        System.out.println(s.verify(signature));
    }
    private static byte[] decodeFromB64(byte[] b){
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(b);

    }
}
