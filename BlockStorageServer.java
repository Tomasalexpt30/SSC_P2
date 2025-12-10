import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;


public class BlockStorageServer {
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));
    private static final int PORT = 5000;
    private static final String BLOCK_DIR = "blockstorage";

    private static final String META_FILE = "metadata.enc";
    private static final String META_KEY_FILE = "server_meta_key.bin";
    private static final String OAS_SIGNING_KEY_FILE = "oas_signing_keypair.bin"; 

    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    private static SecretKey metaKey;
    private static PublicKey oasPublicKey; 
    private static final SecureRandom RNG = new SecureRandom();

    private static final int MAX_CIPHER_LEN = 64 * 1024 * 1024; 
    private static final int MAX_TAG_LEN = 64;                  
    private static final int MAX_META_COUNT = 10_000;           

    private static final String HASH_INDEX_FILE = "hash_index.ser";
    private static Map<String, String> hashToBlockId =
            Collections.synchronizedMap(new HashMap<>());

    private static Map<String, Set<String>> tokenIndex =
            Collections.synchronizedMap(new HashMap<>());

    private static Map<String, List<String>> docToBlocks =
            Collections.synchronizedMap(new HashMap<>());

    private static Map<String, byte[]> blockAuthTags =
            Collections.synchronizedMap(new HashMap<>());

    private static class MetaBlob implements Serializable {
        Map<String, Set<String>> tokenIndex;
        Map<String, List<String>> docToBlocks;
        Map<String, byte[]> blockAuthTags;

        MetaBlob(Map<String, Set<String>> a,
                 Map<String, List<String>> b,
                 Map<String, byte[]> c) {
            this.tokenIndex = a;
            this.docToBlocks = b;
            this.blockAuthTags = c;
        }
    }

    public static void main(String[] args) {
        File dir = new File(BLOCK_DIR);
        if (!dir.exists()) dir.mkdir();
        try {
            metaKey = getOrCreateKey();
            oasPublicKey = loadOasPublicKey(); 
            loadMetadata();
            loadHashIndex();
        } catch (Exception e) {
            System.err.println("WARN: Falha a inicializar OBSS: " + e.getMessage());
        }

        System.out.println("[OBSS Stats]");
        System.out.println(" - Blocos Únicos: " + hashToBlockId.size());
        System.out.println(" - Documentos: " + docToBlocks.size());
        System.out.println(" - Keywords: " + tokenIndex.size());

        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nA encerrar OBSS... a guardar metadados.");
            try { saveMetadata(); } catch (Exception e) { e.printStackTrace(); }
        }));

        try {
            SSLServerSocketFactory sslFactory =
                    (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket =
                         (SSLServerSocket) sslFactory.createServerSocket(PORT)) {

                String[] wanted = Arrays.stream(serverSocket.getEnabledProtocols())
                        .filter(p -> p.equals("TLSv1.3") || p.equals("TLSv1.2"))
                        .toArray(String[]::new);
                if (wanted.length > 0) serverSocket.setEnabledProtocols(wanted);

                System.out.println("Secure BlockStorageServer (TLS) a escutar na porta " + PORT);

                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    new Thread(() -> handleClient(clientSocket)).start();
                }
            }
        } catch (IOException e) {
            System.err.println("Erro Fatal no Servidor: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (
                DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))
        ) {
            while (true) {
                String command;
                try {
                    command = in.readUTF();
                } catch (EOFException eof) {
                    break;
                }

                switch (command) {
                    case "STORE_BLOCK":
                        storeBlock(in, out);
                        break;
                    case "GET_BLOCK":
                        getBlock(in, out);
                        break;
                    case "SEARCH":
                        searchByToken(in, out);
                        break;
                    case "GET_DOC_BLOCKS":
                        getDocBlocks(in, out);
                        break;
                    case "EXIT":
                        return;
                    default:
                        out.writeUTF("ERROR: Unknown command");
                        out.flush();
                        break;
                }
            }
        } catch (IOException e) {
            System.err.println("Erro na conexão: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static void storeBlock(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Falta scope obss:share");
            }

            String blockId = in.readUTF();        
            String plaintextHash = in.readUTF();  

            int cipherLen = in.readInt();
            if (cipherLen < 0 || cipherLen > MAX_CIPHER_LEN) {
                throw new IOException("Tamanho de cipher inválido: " + cipherLen);
            }
            byte[] ivAndCipher = new byte[cipherLen];
            if (cipherLen > 0) {
                in.readFully(ivAndCipher);
            }

            int tagLen = in.readInt();
            if (tagLen < 0 || tagLen > MAX_TAG_LEN) {
                throw new IOException("Tamanho de tag inválido: " + tagLen);
            }
            byte[] authTag = new byte[tagLen];
            if (tagLen > 0) in.readFully(authTag);

            int metaCount = in.readInt();
            if (metaCount < 1 || metaCount > MAX_META_COUNT) {
                throw new IOException("metaCount inválido: " + metaCount);
            }

            String docId = in.readUTF();
            List<String> keywords = new ArrayList<>();
            for (int i = 0; i < metaCount - 1; i++) {
                keywords.add(in.readUTF());
            }

            String finalPhysicalId = blockId;
            boolean isDuplicate = false;

            synchronized (hashToBlockId) {
                if (hashToBlockId.containsKey(plaintextHash)) {
                    finalPhysicalId = hashToBlockId.get(plaintextHash);
                    isDuplicate = true;
                    System.out.println("[Dedup] Hit para hash: " +
                            plaintextHash.substring(0, Math.min(8, plaintextHash.length())));
                } else {
                    hashToBlockId.put(plaintextHash, blockId);
                    saveHashIndex();
                }
            }

            synchronized (docToBlocks) {
                docToBlocks
                        .computeIfAbsent(docId, k -> new ArrayList<>())
                        .add(finalPhysicalId);
            }

            synchronized (tokenIndex) {
                for (String k : keywords) {
                    tokenIndex
                            .computeIfAbsent(k, s -> new HashSet<>())
                            .add(docId);
                }
            }

            synchronized (blockAuthTags) {
                if (!blockAuthTags.containsKey(finalPhysicalId) && tagLen > 0) {
                    blockAuthTags.put(finalPhysicalId, authTag);
                }
            }

            if (!isDuplicate) {
                File blockFile = new File(BLOCK_DIR, finalPhysicalId);
                try (FileOutputStream fos = new FileOutputStream(blockFile)) {
                    fos.write(ivAndCipher);
                }
            }

            saveMetadata();
            out.writeUTF(isDuplicate ? "OK_DUP" : "OK");
            out.flush();

        } catch (GeneralSecurityException e) {
            System.out.println("Security Error STORE_BLOCK: " + e.getMessage());
            out.writeUTF("ERROR:UNAUTHORIZED");
            out.flush();
        }
    }

    private static void getBlock(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // 1. Autorização
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Falta scope obss:get");
            }
            String blockId = in.readUTF();
            File blockFile = new File(BLOCK_DIR, blockId);

            if (!blockFile.exists()) {
                out.writeInt(0);
                out.writeInt(0); 
                out.flush();
                return;
            }

            byte[] ivAndCipher = new byte[(int) blockFile.length()];
            try (FileInputStream fis = new FileInputStream(blockFile)) {
                int read = fis.read(ivAndCipher);
                if (read != ivAndCipher.length) {
                    throw new IOException("Leitura incompleta do bloco");
                }
            }
                    
            byte[] tag;
            synchronized (blockAuthTags) {
                tag = blockAuthTags.getOrDefault(blockId, new byte[0]);
            }

            out.writeInt(ivAndCipher.length);
            out.write(ivAndCipher);
            out.writeInt(tag.length);
            out.write(tag);
            out.flush();
             
        } catch (GeneralSecurityException e) {
            System.out.println("Security Error GET_BLOCK: " + e.getMessage());
            out.writeInt(0);
            out.writeInt(0);
            out.flush();
        }
    }

    private static void searchByToken(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:search")) {
                throw new GeneralSecurityException("Falta scope obss:search");
            }
            String searchToken = in.readUTF(); 
            Set<String> docs;
            synchronized (tokenIndex) {
                docs = tokenIndex.getOrDefault(searchToken, Collections.emptySet());
            }
            out.writeInt(docs.size());
            for (String d : docs) {
                out.writeUTF(d);
            }
            out.flush();
        } catch (GeneralSecurityException e) {
            System.out.println("Security Error SEARCH: " + e.getMessage());
            out.writeInt(0);
            out.flush();
        }
    }

    private static void getDocBlocks(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Falta scope obss:get");
            }

            String docId = in.readUTF();
            List<String> blocks;
            synchronized (docToBlocks) {
                blocks = docToBlocks.getOrDefault(docId, Collections.emptyList());
            }

            out.writeInt(blocks.size());
            for (String b : blocks) {
                out.writeUTF(b);
            }
            out.flush();

        } catch (GeneralSecurityException e) {
            System.out.println("Security Error GET_DOC_BLOCKS: " + e.getMessage());
            // Sem autorização => 0 blocos
            out.writeInt(0);
            out.flush();
        }
    }

    private static boolean hasScope(String scopeStr, String wanted) {
        if (scopeStr == null || scopeStr.isBlank()) return false;
        String[] parts = scopeStr.split("\\s+");
        for (String p : parts) if (p.equalsIgnoreCase(wanted)) return true;
        return false;
    }

    private static PublicKey loadOasPublicKey() throws IOException, GeneralSecurityException {
        File f = new File(OAS_SIGNING_KEY_FILE);
        if (!f.exists())
            throw new IOException("Ficheiro de chave pública OAS não encontrado: " + OAS_SIGNING_KEY_FILE);

        try (DataInputStream in = new DataInputStream(new FileInputStream(f))) {
            int pubLen = in.readInt();
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        }
    }

    private static SecretKey getOrCreateKey() throws IOException {
        File f = new File(META_KEY_FILE);
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new SecretKeySpec(raw, "AES");
            } catch (Exception e) {
                throw new IOException(e);
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

    @SuppressWarnings("unchecked")
    private static void loadHashIndex() {
        File f = new File(HASH_INDEX_FILE);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            Object obj = ois.readObject();
            if (obj instanceof Map) {
                hashToBlockId = Collections.synchronizedMap((Map<String, String>) obj);
            }
        } catch (Exception e) {
            System.err.println("Erro hash index: " + e.getMessage());
        }
    }

    private static void saveHashIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(HASH_INDEX_FILE))) {
            oos.writeObject(hashToBlockId);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void saveMetadata() {
        try {
            MetaBlob blob = new MetaBlob(tokenIndex, docToBlocks, blockAuthTags);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();

            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, metaKey, spec);
            byte[] ct = cipher.doFinal(plain);

            try (FileOutputStream fos = new FileOutputStream(META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
            saveHashIndex(); 
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadMetadata() throws IOException {
        File f = new File(META_FILE);
        if (!f.exists()) return;
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;

            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);

            Cipher cipher = Cipher.getInstance(META_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, metaKey, spec);
            byte[] plain = cipher.doFinal(ct);

            try (ObjectInputStream ois =
                         new ObjectInputStream(new ByteArrayInputStream(plain))) {
                MetaBlob blob = (MetaBlob) ois.readObject();
                if (blob.tokenIndex != null) {
                    tokenIndex = Collections.synchronizedMap(blob.tokenIndex);
                }
                if (blob.docToBlocks != null) {
                    docToBlocks = Collections.synchronizedMap(blob.docToBlocks);
                }
                if (blob.blockAuthTags != null) {
                    blockAuthTags = Collections.synchronizedMap(blob.blockAuthTags);
                }
            }
        } catch (Exception e) {
            throw new IOException("Falha metadados: " + e.getMessage());
        }
    }
}
