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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class ObliviousAccessServer {

    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));
    private static final int PORT = 7000;

    private static final String ACL_META_FILE = "oams_acls.enc";
    private static final String ACL_META_KEY_FILE = "oams_meta_key.bin";
    private static final String OAS_SIGNING_KEYPAIR_FILE = "oas_signing_keypair.bin";
    private static final String OAMS_SIGNING_KEYPAIR_FILE = "oams_signing_keypair.bin";

    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;
    private static final String SIGN_ALGO = "SHA256withECDSA";
    private static final long TIMESTAMP_TOLERANCE_MS = 300_000; // 5 min

    private static final SecureRandom RNG = new SecureRandom();

    public static class AccessEntry implements java.io.Serializable {
        public String docId;
        public String ownerFingerprint;
        public String granteeFingerprint;
        public String permissions;       
        public byte[] encryptedKeyBlob;  

        public AccessEntry(String docId, String ownerFingerprint, String granteeFingerprint,
                           String permissions, byte[] encryptedKeyBlob) {
            this.docId = docId;
            this.ownerFingerprint = ownerFingerprint;
            this.granteeFingerprint = granteeFingerprint;
            this.permissions = permissions;
            this.encryptedKeyBlob = encryptedKeyBlob;
        }
    }

    public static class AclMetaBlob implements java.io.Serializable {
        public Map<String, List<AccessEntry>> aclByDoc;
        public AclMetaBlob(Map<String, List<AccessEntry>> aclByDoc) {
            this.aclByDoc = aclByDoc;
        }
    }

    private static Map<String, List<AccessEntry>> aclByDoc =
            Collections.synchronizedMap(new HashMap<>());

    private static SecretKey aclMetaKey;
    private static PublicKey oasPublicKey;    
    private static PrivateKey oamsPrivateKey; 

    public static void main(String[] args) {
        try {
            aclMetaKey = getOrCreateMetaKey();
            loadAclMetadata();
            oasPublicKey = loadOasPublicKey();
            KeyPair oamsKp = getOrCreateSigningKeyPair();
            oamsPrivateKey = oamsKp.getPrivate();
            System.out.println("OAMS iniciado: docIds com ACLs = " + aclByDoc.size());
        } catch (Exception e) {
            System.err.println("Falha a inicializar OAMS: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        try {
            SSLServerSocketFactory sslFactory =
                    (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslFactory.createServerSocket(PORT)) {
                String[] enabled = serverSocket.getEnabledProtocols();
                serverSocket.setEnabledProtocols(Arrays.stream(enabled)
                        .filter(p -> p.equals("TLSv1.2") || p.equals("TLSv1.3"))
                        .toArray(String[]::new));
                System.out.println("ObliviousAccessServer (OAMS) a escutar em TLS na porta " + PORT);
                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    new Thread(() -> handleClient(clientSocket)).start();
                }
            }
        } catch (IOException e) {
            System.err.println("Erro no servidor OAMS (TLS): " + e.getMessage());
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
                    case "CREATE_SHARE":
                        handleCreateShare(in, out);
                        break;
                    case "DELETE_SHARE":
                        handleDeleteShare(in, out);
                        break;
                    case "CHECK_ACCESS":
                        handleCheckAccess(in, out);
                        break;
                    case "EXIT":
                        System.out.println("Cliente OAMS enviou EXIT.");
                        return;
                    default:
                        sendSignedResponse(out, "ERROR:UNKNOWN_COMMAND");
                        break;
                }
            }

        } catch (IOException e) {
            System.err.println("Erro ligação OAMS: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static void handleCreateShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String jwtToken = in.readUTF();
            String docId = in.readUTF();
            String granteeFp = in.readUTF();
            String permissions = in.readUTF();
            int keyBlobLen = in.readInt();
            byte[] keyBlob = new byte[keyBlobLen];
            if (keyBlobLen > 0) in.readFully(keyBlob);

            long timestamp = in.readLong();
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String ownerFp = payload.subject;

            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Token sem scope obss:share");
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CREATE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(granteeFp);
            dos.writeUTF(permissions);
            dos.writeInt(keyBlobLen);
            if (keyBlobLen > 0) dos.write(keyBlob);
            dos.writeLong(timestamp);

            validateRequestSignature(ownerFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            AccessEntry entry =
                    new AccessEntry(docId, ownerFp, granteeFp, permissions, keyBlob);

            synchronized (aclByDoc) {
                List<AccessEntry> list =
                        aclByDoc.computeIfAbsent(docId, k -> new ArrayList<>());
                list.removeIf(e ->
                        e.ownerFingerprint.equals(ownerFp) &&
                        e.granteeFingerprint.equals(granteeFp));
                list.add(entry);
            }
            saveAclMetadata();

            System.out.println("CREATE_SHARE: OK " +
                    ownerFp.substring(0, 8) + " -> " + granteeFp.substring(0, 8));
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            System.err.println("CREATE_SHARE error: " + e.getMessage());
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void handleDeleteShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String jwtToken = in.readUTF();
            String docId = in.readUTF();
            String granteeFp = in.readUTF();

            long timestamp = in.readLong();
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String ownerFp = payload.subject;

            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Token sem scope obss:share");
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(granteeFp);
            dos.writeLong(timestamp);

            validateRequestSignature(ownerFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            boolean removed;
            synchronized (aclByDoc) {
                List<AccessEntry> list = aclByDoc.get(docId);
                if (list != null) {
                    removed = list.removeIf(e ->
                            e.ownerFingerprint.equals(ownerFp) &&
                            e.granteeFingerprint.equals(granteeFp));
                    if (list.isEmpty()) aclByDoc.remove(docId);
                } else {
                    removed = false;
                }
            }

            if (removed) {
                saveAclMetadata();
                sendSignedResponse(out, "OK");
            } else {
                sendSignedResponse(out, "ERROR:NOT_FOUND");
            }

        } catch (Exception e) {
            System.err.println("DELETE_SHARE error: " + e.getMessage());
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void handleCheckAccess(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String jwtToken = in.readUTF();
            String docId = in.readUTF();
            String requestedPermRaw = in.readUTF();
            String requestedPerm = requestedPermRaw.toUpperCase(Locale.ROOT).trim();

            long timestamp = in.readLong();
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String subjectFp = payload.subject;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CHECK_ACCESS");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(requestedPermRaw);
            dos.writeLong(timestamp);

            validateRequestSignature(subjectFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            boolean wantsSearch = requestedPerm.contains("SEARCH");
            boolean wantsGet = requestedPerm.contains("GET");

            if (wantsSearch && !hasScope(payload.scope, "obss:search")) {
                throw new GeneralSecurityException("Token sem scope obss:search");
            }
            if (wantsGet && !hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Token sem scope obss:get");
            }

            byte[] keyBlobToSend = new byte[0];
            boolean allowed = false;

            if (docId.equals("ANY") && wantsSearch) {
                allowed = true;
            } else {
                synchronized (aclByDoc) {
                    List<AccessEntry> list = aclByDoc.get(docId);
                    if (list != null) {
                        for (AccessEntry e : list) {
                            if (e.ownerFingerprint.equals(subjectFp)
                                    || e.granteeFingerprint.equals(subjectFp)) {
                                boolean aclHasGet = permContains(e.permissions, "GET");
                                boolean aclHasSearch = permContains(e.permissions, "SEARCH");

                                boolean okAcl =
                                        (!wantsGet || aclHasGet) &&
                                        (!wantsSearch || aclHasSearch);

                                if (okAcl) {
                                    allowed = true;
                                    if (e.encryptedKeyBlob != null) {
                                        keyBlobToSend = e.encryptedKeyBlob;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (allowed) {
                ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
                DataOutputStream respDos = new DataOutputStream(respBaos);
                respDos.writeUTF("OK");
                respDos.writeInt(keyBlobToSend.length);
                if (keyBlobToSend.length > 0) respDos.write(keyBlobToSend);

                byte[] dataToSign = respBaos.toByteArray();
                byte[] sig = signData(dataToSign);

                out.writeUTF("OK");
                out.writeInt(keyBlobToSend.length);
                if (keyBlobToSend.length > 0) out.write(keyBlobToSend);
                out.writeInt(sig.length);
                out.write(sig);
                out.flush();
            } else {
                sendSignedResponse(out, "DENY");
            }

        } catch (Exception e) {
            System.err.println("CHECK_ACCESS error: " + e.getMessage());
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    private static void validateRequestSignature(String jwtSubjectFp, byte[] clientPubKeyBytes, byte[] signedData, byte[] signature, long timestamp) throws GeneralSecurityException {

        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_MS) {
            throw new GeneralSecurityException("Timestamp expirado ou inválido (Replay?)");
        }

        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey clientPubKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));

        String calculatedFp = JwtUtils.publicKeyFingerprint(clientPubKey);
        if (!calculatedFp.equals(jwtSubjectFp)) {
            throw new GeneralSecurityException("Chave pública não corresponde ao subject do JWT");
        }

        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initVerify(clientPubKey);
        sig.update(signedData);
        if (!sig.verify(signature)) {
            throw new GeneralSecurityException("Assinatura do pedido inválida");
        }
    }

    private static void sendSignedResponse(DataOutputStream out, String msg) throws IOException {
        try {
            byte[] data = msg.getBytes(StandardCharsets.UTF_8);
            byte[] signature = signData(data);

            out.writeUTF(msg);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();
        } catch (GeneralSecurityException e) {
            throw new IOException("Falha a assinar resposta OAMS", e);
        }
    }

    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(oamsPrivateKey);
        sig.update(data);
        return sig.sign();
    }

    private static KeyPair getOrCreateSigningKeyPair() throws IOException, GeneralSecurityException {
        File f = new File(OAMS_SIGNING_KEYPAIR_FILE);
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
            System.out.println("Gerado novo par de chaves OAMS em " + OAMS_SIGNING_KEYPAIR_FILE);
            return kp;
        }
    }

    private static boolean hasScope(String scopeStr, String wanted) {
        if (scopeStr == null || scopeStr.isBlank()) return false;
        String[] parts = scopeStr.split("\\s+");
        for (String p : parts) {
            if (p.equalsIgnoreCase(wanted)) return true;
        }
        return false;
    }

    private static boolean permContains(String perms, String wanted) {
        if (perms == null) return false;
        String[] parts = perms.split("[,\\s]+");
        for (String p : parts) {
            if (p.equalsIgnoreCase(wanted)) return true;
        }
        return false;
    }

    private static SecretKey getOrCreateMetaKey() throws IOException {
        File f = new File(ACL_META_KEY_FILE);
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new javax.crypto.spec.SecretKeySpec(raw, "AES");
            }
        } else {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(META_KEY_BITS);
                SecretKey key = kg.generateKey();
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    fos.write(Base64.getEncoder().encode(key.getEncoded()));
                }
                return key;
            } catch (Exception e) {
                throw new IOException(e);
            }
        }
    }

    private static void saveAclMetadata() {
        try {
            AclMetaBlob blob = new AclMetaBlob(aclByDoc);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, aclMetaKey,
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain);
            try (FileOutputStream fos = new FileOutputStream(ACL_META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadAclMetadata() throws IOException {
        File f = new File(ACL_META_FILE);
        if (!f.exists()) return;
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;
            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, aclMetaKey,
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plain = cipher.doFinal(ct);
            try (ObjectInputStream ois =
                         new ObjectInputStream(new ByteArrayInputStream(plain))) {
                AclMetaBlob blob = (AclMetaBlob) ois.readObject();
                if (blob.aclByDoc != null) {
                    aclByDoc = Collections.synchronizedMap(blob.aclByDoc);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PublicKey loadOasPublicKey() throws IOException, GeneralSecurityException {
        File f = new File(OAS_SIGNING_KEYPAIR_FILE);
        try (DataInputStream in = new DataInputStream(new FileInputStream(f))) {
            int pubLen = in.readInt();
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        }
    }
}
