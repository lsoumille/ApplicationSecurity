import com.polytech.SqueletonEntity;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * Created by lucas on 18/01/17.
 */
public class SecureKeyExchange {

    public static void main(String[] args) {
        // create two new entity
        SqueletonEntity Alice = new SqueletonEntity();
        SqueletonEntity Bob = new SqueletonEntity();

        try {
            //Send public key
            System.out.println("ALICE send PublicKey = " + Alice.thePublicKey);
            //Bob generates DES session key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            Key sessionKey = keyGenerator.generateKey();
            System.out.println("BOB create DES key = " + Arrays.toString(sessionKey.getEncoded()));
            //Bob encrypts DES key
            byte[] encryptedKey = Bob.encrypt(sessionKey.getEncoded(), Alice.thePublicKey);
            System.out.println("Encrypted key by Bob using Alice public key = ");
            System.out.println(new String(encryptedKey));
            //Alice decrypts DES key using her private key
            byte[] DESKeyDecrypted = Alice.decrypt(encryptedKey);
            System.out.println("Decrypted key by Alice using her private key = " + Arrays.toString(DESKeyDecrypted));
            //Alice sends message with DES Key
            Cipher DESc = Cipher.getInstance("DES");
            DESc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(DESKeyDecrypted, 0, DESKeyDecrypted.length, "DES"));
            byte[] encryptedMessage = DESc.doFinal("BONJOUR JE SUIS ALICE".getBytes());
            System.out.println("Plain text = BONJOUR JE SUIS ALICE");
            System.out.println("Encrypted message by Alice using DES key = " + new String(encryptedMessage));
            //Bob receives and decrypts the message
            Cipher DESd = Cipher.getInstance("DES");
            DESd.init(Cipher.DECRYPT_MODE, sessionKey);
            byte[] message = DESd.doFinal(encryptedMessage);
            System.out.println("Message received and decrypted by Bob = " + new String(message));
        } catch (Exception e) {

        }
    }
}
