import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class ObliviousAuthServer {
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));
    private static final int PORT = 6000;

    private static final String USERS_META_FILE = "oas_users.enc";
    private static final String USERS_META_KEY_FILE = "oas_users_meta_key.bin";
    private static final String SIGNING_KEY_FILE = "oas_signing_keypair.bin";

    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;
    private static final String SIGN_ALGO = "SHA256withECDSA";
    private static final long TIMESTAMP_TOLERANCE_MS = 300_000; 
    private static final long TOKEN_TTL_SECONDS = 300;

    private static final SecureRandom RNG = new SecureRandom();

    private static class UserRecord implements java.io.Serializable {
        byte[]  publicKeyEncoded;  
        String  pubKeyFingerprint; 
        byte[]  pwdSalt;          
        byte[]  pwdHash;           
        Map<String, String> attributes; 

        UserRecord(byte[] publicKeyEncoded, String pubKeyFingerprint, byte[] pwdSalt, byte[] pwdHash, Map<String, String> attributes) {
            this.publicKeyEncoded = publicKeyEncoded;
            this.pubKeyFingerprint = pubKeyFingerprint;
            this.pwdSalt = pwdSalt;
            this.pwdHash = pwdHash;
            this.attributes = (attributes != null) ? attributes : new HashMap<>();
        }
    }

    private static class UsersMetaBlob implements java.io.Serializable {
        Map<String, UserRecord> users;
        UsersMetaBlob(Map<String, UserRecord> users) { this.users = users; }
    }

    private static Map<String, UserRecord> users = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, byte[]> activeNonces = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, Long> issuedTokens = Collections.synchronizedMap(new HashMap<>());
    private static SecretKey usersMetaKey;
    private static KeyPair signingKeyPair; 
    public static void main(String[] args) {
        try {
            usersMetaKey = getOrCreateMetaKey();
            loadUsersMetadata();
            signingKeyPair = getOrCreateSigningKeyPair();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Falha a inicializar OAS: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        System.out.println("OAS iniciado: utilizadores carregados = " + users.size());

        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        try {
            SSLServerSocketFactory sslFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslFactory.createServerSocket(PORT)) {
                
                String[] enabled = serverSocket.getEnabledProtocols();
                serverSocket.setEnabledProtocols(Arrays.stream(enabled)
                        .filter(p -> p.equals("TLSv1.2") || p.equals("TLSv1.3"))
                        .toArray(String[]::new));

                System.out.println("ObliviousAuthServer (OAS) a escutar em TLS na porta " + PORT);
                new Thread(ObliviousAuthServer::cleanupExpiredTokens).start();

                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("Cliente OAS ligado: " + clientSocket.getInetAddress());
                    new Thread(() -> handleClient(clientSocket)).start();
                }
            }
        } catch (IOException e) {
            System.err.println("Erro no servidor OAS (TLS): " + e.getMessage());
            e.printStackTrace();
        }
    }
    private static void handleClient(Socket socket) {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {

            while (true) {
                String cmd;
                try {
                    cmd = in.readUTF();
                } catch (EOFException eof) {
                    break;
                }

                switch (cmd) {
                    case "CREATE_REG":
                        handleCreateRegistration(in, out);
                        break;
                    case "MODIFY_REG":
                        handleModifyRegistration(in, out);
                        break;
                    case "DELETE_REG":
                        handleDeleteRegistration(in, out);
                        break;
                    case "AUTH_START":
                        handleAuthStart(in, out);
                        break;
                    case "AUTH_FINISH":
                        handleAuthFinish(in, out);
                        break;
                    case "EXIT":
                        System.out.println("Cliente OAS enviou EXIT.");
                        return;
                    default:
                        sendSignedResponse(out, "ERROR:UNKNOWN_COMMAND");
                        break;
                }
            }

        } catch (IOException e) {
            System.err.println("Erro ligação OAS: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static void handleCreateRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            String password = in.readUTF(); 
            
            int attrCount = in.readInt();
            Map<String, String> attrs = new HashMap<>();
            for (int i = 0; i < attrCount; i++) {
                attrs.put(in.readUTF(), in.readUTF());
            }

            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CREATE_REG");
            dos.writeInt(pubLen);
            dos.write(pubBytes);
            dos.writeUTF(password);
            dos.writeInt(attrCount);
            for (Map.Entry<String, String> entry : attrs.entrySet()) {
                dos.writeUTF(entry.getKey());
                dos.writeUTF(entry.getValue());
            }
            dos.writeLong(timestamp);
            
            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                if (users.containsKey(fingerprint)) {
                    sendSignedResponse(out, "ERROR:ALREADY_REGISTERED");
                    return;
                }

                byte[] salt = new byte[16];
                RNG.nextBytes(salt);
                byte[] hash = pbkdf2(password.toCharArray(), salt, 200_000, 32);

                UserRecord rec = new UserRecord(pubBytes, fingerprint, salt, hash, attrs);
                users.put(fingerprint, rec);
            }
            saveUsersMetadata();

            System.out.println("Registo criado: " + fingerprint.substring(0, 8));
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void handleModifyRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            String currentPwd = in.readUTF();
            String newPwd = in.readUTF();
            
            int attrCount = in.readInt();
            Map<String, String> newAttrs = new HashMap<>();
            for (int i = 0; i < attrCount; i++) {
                newAttrs.put(in.readUTF(), in.readUTF());
            }

            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("MODIFY_REG");
            dos.writeInt(pubLen);
            dos.write(pubBytes);
            dos.writeUTF(currentPwd);
            dos.writeUTF(newPwd);
            dos.writeInt(attrCount);
            for (Map.Entry<String, String> e : newAttrs.entrySet()) {
                dos.writeUTF(e.getKey());
                dos.writeUTF(e.getValue());
            }
            dos.writeLong(timestamp);

            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                UserRecord rec = users.get(fingerprint);
                if (rec == null) {
                    sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                    return;
                }

                byte[] checkHash = pbkdf2(currentPwd.toCharArray(), rec.pwdSalt, 200_000, 32);
                if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                    sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                    return;
                }

                if (newPwd != null && !newPwd.isBlank()) {
                    byte[] newSalt = new byte[16];
                    RNG.nextBytes(newSalt);
                    byte[] newHash = pbkdf2(newPwd.toCharArray(), newSalt, 200_000, 32);
                    rec.pwdSalt = newSalt;
                    rec.pwdHash = newHash;
                }
                rec.attributes = newAttrs;
            }
            saveUsersMetadata();
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void handleDeleteRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            String password = in.readUTF();

            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_REG");
            dos.writeInt(pubLen);
            dos.write(pubBytes);
            dos.writeUTF(password);
            dos.writeLong(timestamp);

            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                UserRecord rec = users.get(fingerprint);
                if (rec == null) {
                    sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                    return;
                }
                byte[] checkHash = pbkdf2(password.toCharArray(), rec.pwdSalt, 200_000, 32);
                if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                    sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                    return;
                }
                users.remove(fingerprint);
                activeNonces.remove(fingerprint);
            }
            saveUsersMetadata();
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }


    private static void handleAuthStart(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);


            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            if (!users.containsKey(fingerprint)) {
                sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                return;
            }

            byte[] nonce = new byte[32];
            RNG.nextBytes(nonce);
            activeNonces.put(fingerprint, nonce);

            out.writeUTF("OK");
            out.writeInt(nonce.length);
            out.write(nonce);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("OK");
            dos.writeInt(nonce.length);
            dos.write(nonce);
            byte[] sig = signData(baos.toByteArray());
            
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void handleAuthFinish(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);
            String password = in.readUTF();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);
            UserRecord rec = users.get(fingerprint);

            if (rec == null) {
                sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                return;
            }

            byte[] nonce = activeNonces.remove(fingerprint);
            if (nonce == null) {
                sendSignedResponse(out, "ERROR:NO_ACTIVE_CHALLENGE");
                return;
            }

            byte[] checkHash = pbkdf2(password.toCharArray(), rec.pwdSalt, 200_000, 32);
            if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                return;
            }

            String nonceB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
            String msg = "AUTH|" + fingerprint + "|" + nonceB64;

            if (!verifyEcSignature(msg.getBytes(StandardCharsets.UTF_8), signature, pk)) {
                sendSignedResponse(out, "ERROR:BAD_SIGNATURE");
                return;
            }

            String jti = UUID.randomUUID().toString();

            String token = JwtUtils.generateToken(
                signingKeyPair.getPrivate(), 
                "OAS", 
                fingerprint, 
                TOKEN_TTL_SECONDS, 
                "obss:get obss:search obss:share",
                jti 
            );

            issuedTokens.put(jti, System.currentTimeMillis() + (TOKEN_TTL_SECONDS * 1000));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("OK");
            dos.writeUTF(token);
            byte[] respSig = signData(baos.toByteArray());

            out.writeUTF("OK");
            out.writeUTF(token);
            out.writeInt(respSig.length);
            out.write(respSig);
            out.flush();

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void validateRequestSignature(byte[] clientPubKeyBytes, byte[] signedData, byte[] signature, long timestamp) throws GeneralSecurityException {
        long now = System.currentTimeMillis();
    
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_MS) {
            throw new GeneralSecurityException("Timestamp inválido ou expirado (Replay?)");
        }

        PublicKey clientKey = decodeEcPublicKey(clientPubKeyBytes);
        if (!verifyEcSignature(signedData, signature, clientKey)) {
            throw new GeneralSecurityException("Assinatura do pedido inválida");
        }
    }

    private static void sendSignedResponse(DataOutputStream out, String msg) throws IOException {
        try {
            byte[] data = msg.getBytes(StandardCharsets.UTF_8);
            byte[] sig = signData(data);

            out.writeUTF(msg);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();
        } catch (GeneralSecurityException e) {
            throw new IOException("Falha a assinar resposta", e);
        }
    }


    private static void cleanupExpiredTokens() {
        while (true) {
            try {
                Thread.sleep(60000);
                long now = System.currentTimeMillis();
                synchronized (issuedTokens) {
                    Iterator<Map.Entry<String, Long>> it = issuedTokens.entrySet().iterator();
                    while (it.hasNext()) {
                        if (it.next().getValue() < now) {
                            it.remove();
                        }
                    }
                }
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(signingKeyPair.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    private static boolean verifyEcSignature(byte[] data, byte[] signature, PublicKey key) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    private static PublicKey decodeEcPublicKey(byte[] encoded) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iters, int keyLenBytes) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iters, keyLenBytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    private static SecretKey getOrCreateMetaKey() throws IOException {
        File f = new File(USERS_META_KEY_FILE);
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new javax.crypto.spec.SecretKeySpec(raw, "AES");
            } catch (Exception e) { throw new IOException(e); }
        } else {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(META_KEY_BITS);
                SecretKey key = kg.generateKey();
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    fos.write(Base64.getEncoder().encode(key.getEncoded()));
                }
                return key;
            } catch (Exception e) { throw new IOException(e); }
        }
    }

    private static void saveUsersMetadata() {
        try {
            UsersMetaBlob blob = new UsersMetaBlob(users);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) { oos.writeObject(blob); }
            byte[] plain = baos.toByteArray();
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, usersMetaKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain);
            try (FileOutputStream fos = new FileOutputStream(USERS_META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    @SuppressWarnings("unchecked")
    private static void loadUsersMetadata() throws IOException {
        File f = new File(USERS_META_FILE);
        if (!f.exists()) return;
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;
            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, usersMetaKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plain = cipher.doFinal(ct);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
                UsersMetaBlob blob = (UsersMetaBlob) ois.readObject();
                if (blob.users != null) users = Collections.synchronizedMap(blob.users);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    private static KeyPair getOrCreateSigningKeyPair() throws IOException, GeneralSecurityException {
        File f = new File(SIGNING_KEY_FILE);
        if (f.exists()) {
            try (DataInputStream in = new DataInputStream(new FileInputStream(f))) {
                int pubLen = in.readInt();
                byte[] pubBytes = new byte[pubLen];
                in.readFully(pubBytes);
                int privLen = in.readInt();
                byte[] privBytes = new byte[privLen];
                in.readFully(privBytes);
                KeyFactory kf = KeyFactory.getInstance("EC");
                PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
                PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                return new KeyPair(pub, priv);
            }
        } else {
            KeyPair kp = JwtUtils.generateEcKeyPair();
            try (DataOutputStream out = new DataOutputStream(new FileOutputStream(f))) {
                byte[] pub = kp.getPublic().getEncoded();
                byte[] priv = kp.getPrivate().getEncoded();
                out.writeInt(pub.length);
                out.write(pub);
                out.writeInt(priv.length);
                out.write(priv);
            }
            System.out.println("Chave de assinatura OAS gerada: " + SIGNING_KEY_FILE);
            return kp;
        }
    }
}