package testing;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.util.Queue;
import java.util.LinkedList;
import java.util.concurrent.*;
import java.util.*;
import java.nio.ByteBuffer;


class Alex {
    private String publicKey = "";
    private String privateKey = "";
    private String secretKey = "";
    public Queue<byte[]> AlexQ = new LinkedList<>();

    public String getPublicKey() {
        return publicKey; 
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public void generateKey() throws NoSuchAlgorithmException {
    	// Key generation for AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        this.secretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
    
    public void sendKey(Bob bob) throws Exception {
        byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);

        // Sign secret key for RSA
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey))));
        signature.update(secretKeyBytes);
        byte[] signedSecretKey = signature.sign();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(bob.getPublicKey()))));
        byte[] encryptedSecretKey = rsaCipher.doFinal(secretKeyBytes);

        // Combine encryptedSecretKey and signedSecretKey
        byte[] combinedKey = new byte[encryptedSecretKey.length + signedSecretKey.length];
        System.arraycopy(encryptedSecretKey, 0, combinedKey, 0, encryptedSecretKey.length);
        System.arraycopy(signedSecretKey, 0, combinedKey, encryptedSecretKey.length, signedSecretKey.length);

        // Convert encryptedSecretKeyLength to byte array
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(encryptedSecretKey.length);
        byte[] encryptedSecretKeyLengthBytes = b.array();

        bob.BobQ.add(combinedKey);
        bob.BobQ.add(encryptedSecretKeyLengthBytes);
    }

    public void sendMessage(Bob bob) throws Exception {
        String message = "Let us have a meeting tomorrow at 4";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);  

        // Custom padding
        int blockSize = 16; 
        int paddingLength = blockSize - (messageBytes.length % blockSize);
        if (paddingLength != 0) {
            byte[] paddedMessage = new byte[messageBytes.length + paddingLength];
            System.arraycopy(messageBytes, 0, paddedMessage, 0, messageBytes.length);
            messageBytes = paddedMessage;
        }

        // Encrypt Message using secret key and AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = generateIV(aesCipher); 
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES"), iv);
        byte[] encryptedBytes = aesCipher.doFinal(messageBytes);

        
        byte[] combinedMessages = new byte[aesCipher.getBlockSize() + encryptedBytes.length];
        System.arraycopy(iv.getIV(), 0, combinedMessages, 0, aesCipher.getBlockSize());
        System.arraycopy(encryptedBytes, 0, combinedMessages, aesCipher.getBlockSize(), encryptedBytes.length);

        bob.BobQ.add(combinedMessages);   
    }

    public void receiveReply() throws Exception {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new Exception("Secret key is null or empty.");
        }

        byte[] reply = AlexQ.poll();
        if (reply == null) {
            throw new Exception("No reply received from Bob.");
        }

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Extract IV and encrypted reply
        byte[] iv = Arrays.copyOfRange(reply, 0, aesCipher.getBlockSize());
        byte[] encryptedMessage = Arrays.copyOfRange(reply, aesCipher.getBlockSize(), reply.length);

        // Decrypt the reply with secret key and AES
        aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES"), new IvParameterSpec(iv));
        byte[] decryptedBytes = aesCipher.doFinal(encryptedMessage);
        
        int lastIndex = decryptedBytes.length - 1;
        while (lastIndex >= 0 && decryptedBytes[lastIndex] == 0) {
            lastIndex--;
        }

 
        byte[] unpaddedBytes = Arrays.copyOfRange(decryptedBytes, 0, lastIndex + 1);
        //System.out.println("unpadded message bytes: " + Base64.getEncoder().encodeToString(unpaddedBytes )); (testing purposes)

        // Save reply in a string variable and display it
        String message = new String(unpaddedBytes, StandardCharsets.UTF_8);
        System.out.println("Reply from Bob: " + message);
    }

    private IvParameterSpec generateIV(Cipher cipher) {
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}

class Bob {
    private String publicKey = "";
    private String privateKey = "";
    private String secretKey = "";
    public Queue<byte[]> BobQ = new LinkedList<>();

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public void receiveKey(Alex alex) throws Exception {
    	// Extract encrypted and signed key from queue 
        byte[] combinedKey = BobQ.poll();
        byte[] encryptedSecretKeyLengthBytes = BobQ.poll();

        // Separate the combinedKey back into encryptedSecretKey and signedSecretKey
        ByteBuffer wrapped = ByteBuffer.wrap(encryptedSecretKeyLengthBytes);
        int encryptedSecretKeyLength = wrapped.getInt();
        byte[] encryptedSecretKey = Arrays.copyOfRange(combinedKey, 0, encryptedSecretKeyLength);
        byte[] signatureBytes = Arrays.copyOfRange(combinedKey, encryptedSecretKeyLength, combinedKey.length);

        // Decrypt secret key with private key and RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey))));
        byte[] decryptedSecretKey = rsaCipher.doFinal(encryptedSecretKey);

        // Verify Alex's signature, else display a warning
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(alex.getPublicKey()))));
        signature.update(decryptedSecretKey);
        boolean verified = signature.verify(signatureBytes);
        if (verified == true) {
        	System.out.println("Alex Signature is confirmed");
        	this.secretKey = Base64.getEncoder().encodeToString(decryptedSecretKey);
        }
        else {
        	System.out.println("Signature not from Alex");
        }
    }


    public void receiveMessage() throws Exception {
    	// If no secret key is stored, return error message
        if (secretKey == null || secretKey.isEmpty()) {
            throw new Exception("Secret key is null or empty.");
        }

        // Extract encrypted message from Bob's queue, if no message, return error statement
        byte[] combinedMessage = BobQ.poll();
        if (combinedMessage == null) {
            throw new Exception("No message received from Alex.");
        }
        
        byte[] iv = Arrays.copyOfRange(combinedMessage, 0, 16); 
        byte[] encryptedMessage = Arrays.copyOfRange(combinedMessage, 16, combinedMessage.length);

        // Decrypt message with AES and secret key
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES"), new IvParameterSpec(iv));
        byte[] decryptedBytes = aesCipher.doFinal(encryptedMessage);

        int lastIndex = decryptedBytes.length - 1;
        while (lastIndex >= 0 && decryptedBytes[lastIndex] == 0) {
            lastIndex--;
        }

        byte[] unpaddedBytes = Arrays.copyOfRange(decryptedBytes, 0, lastIndex + 1);

        // Save message and display it
        String message = new String(unpaddedBytes, StandardCharsets.UTF_8);
        System.out.println("Message from Alex: " + message);
    } 

    public void sendReply(Alex alex) throws Exception {
    	// Checks if there is a secret key to initiate Bob's reply
        if (secretKey == null || secretKey.isEmpty()) {
            throw new Exception("Secret key is null or empty.");
        }
        
        String reply = "Yes, I can meet you at Student Union";
        byte[] replyBytes = reply.getBytes(StandardCharsets.UTF_8);
        
        //System.out.println("message bytes: " + Base64.getEncoder().encodeToString(replyBytes));

        int blockSize = 16;
        int paddingLength = blockSize - (replyBytes.length % blockSize);
        if (paddingLength != 0) {
            byte[] paddedReply = new byte[replyBytes.length + paddingLength];
            System.arraycopy(replyBytes, 0, paddedReply, 0, replyBytes.length);
            replyBytes = paddedReply;
        }

        // Encrypt Bob's reply with AES and secret key
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(secretKey), "AES"), generateIV(aesCipher));
        byte[] encryptedBytes = aesCipher.doFinal(replyBytes);
        
        // Pads the reply
        byte[] combinedReply = new byte[aesCipher.getBlockSize() + encryptedBytes.length];
        System.arraycopy(aesCipher.getIV(), 0, combinedReply, 0, aesCipher.getBlockSize());
        System.arraycopy(encryptedBytes, 0, combinedReply, aesCipher.getBlockSize(), encryptedBytes.length);

        // Sends reply to Alex's queue
        alex.AlexQ.add(combinedReply);
        
    }

    private IvParameterSpec generateIV(Cipher cipher) {
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}

class ExchangeTest {
    private final CountDownLatch keySent = new CountDownLatch(1);
    private final CountDownLatch alexMessageSent = new CountDownLatch(1);
    private final CountDownLatch bobMessageSent = new CountDownLatch(1);

    public void test() throws Exception {
    	// Generation of public-private key pairs for Alex and Bob
        Alex alex = new Alex();
        Bob bob = new Bob();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair alexKeyPair = keyGen.generateKeyPair();
        KeyPair bobKeyPair = keyGen.generateKeyPair();

        alex.setPublicKey(Base64.getEncoder().encodeToString(alexKeyPair.getPublic().getEncoded()));
        alex.setPrivateKey(Base64.getEncoder().encodeToString(alexKeyPair.getPrivate().getEncoded()));

        bob.setPublicKey(Base64.getEncoder().encodeToString(bobKeyPair.getPublic().getEncoded()));
        bob.setPrivateKey(Base64.getEncoder().encodeToString(bobKeyPair.getPrivate().getEncoded()));

        // Threading for queue operations
        Thread alexThread = new Thread(() -> {
            try {
                alex.generateKey();
                alex.sendKey(bob);
                keySent.countDown();

                alex.sendMessage(bob);
                alexMessageSent.countDown();

                bobMessageSent.await();
                alex.receiveReply();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        Thread bobThread = new Thread(() -> {
            try {
                keySent.await();
                bob.receiveKey(alex);

                alexMessageSent.await();
                bob.receiveMessage();

                bob.sendReply(alex);
                bobMessageSent.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        alexThread.start();
        bobThread.start();
    }
}

public class Program {
    public static void main(String[] args) throws Exception {
        ExchangeTest exchangeTest = new ExchangeTest();
        exchangeTest.test();

        System.in.read();
    }
}
