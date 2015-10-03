import java.io.FileOutputStream;
import java.nio.file.*;
import java.security.*;
import java.util.Base64;

/**
 * Created by lschubert on 9/30/15.
 */
public class SignatureCreator {
    public static void main(String[] args)throws Exception{
        Path path = Paths.get(args[0]);
        //Path path = Paths.get("/Users/lschubert/Desktop/cs166TestFiles/cipherForQ9.txt");
        byte[] text = Files.readAllBytes(path);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();




        byte[] publicKeyByte = publicKey.getEncoded();
        byte[] b64PublicKey = encodeToB64(publicKeyByte);


        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(text);
        byte[] realSignature = s.sign();
        byte[] b64Signature = encodeToB64(realSignature);


        FileOutputStream fos = new FileOutputStream("signature");
        fos.write(b64Signature);
        fos.close();

        FileOutputStream keyOutput = new FileOutputStream("publicKey");
        keyOutput.write(b64PublicKey);
        keyOutput.close();
    }
    private static byte[] encodeToB64(byte[] b){
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encode(b);

    }
}
