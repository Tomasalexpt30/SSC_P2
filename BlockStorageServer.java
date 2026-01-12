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

    // Lê/valida a configuração criptográfica do ficheiro cryptoconfig.txt
    // (mesmo que não seja usada diretamente aqui, garante que o projeto está com AES/GCM/NoPadding, etc.)
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));

    // Porta do OBSS (Oblivious Block Storage Server)
    private static final int PORT = 5000;

    // Diretório onde os blocos (ciphertext) são guardados fisicamente no disco
    private static final String BLOCK_DIR = "blockstorage";

    // Ficheiro que guarda metadados do OBSS (índices, doc->blocos, tags) cifrado (AES-GCM)
    private static final String META_FILE = "metadata.enc";

    // Ficheiro que contém a chave AES do servidor para cifrar/decifrar META_FILE
    private static final String META_KEY_FILE = "server_meta_key.bin";

    // Ficheiro com o keypair do OAS (aqui o OBSS lê a chave pública para validar JWT)
    private static final String OAS_SIGNING_KEY_FILE = "oas_signing_keypair.bin";

    // Cipher usado para cifrar metadados do servidor (persistência)
    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    // Chave AES do servidor para cifrar/decifrar os metadados (META_FILE)
    private static SecretKey metaKey;

    // Chave pública do OAS para verificar assinaturas dos JWT emitidos por ele
    private static PublicKey oasPublicKey;

    // RNG para nonces/IVs (AES-GCM)
    private static final SecureRandom RNG = new SecureRandom();

    // Limites defensivos para evitar ataques de memória / inputs maliciosos
    private static final int MAX_CIPHER_LEN = 64 * 1024 * 1024; // 64MB por bloco
    private static final int MAX_TAG_LEN = 64;                  // tags "custom" (não GCM) guardadas à parte
    private static final int MAX_META_COUNT = 10_000;           // número máximo de strings de metadata por pedido

    // Ficheiro separado para persistir o índice de deduplicação (hash->blockId físico)
    private static final String HASH_INDEX_FILE = "hash_index.ser";

    // Deduplicação: plaintextHash -> blockId físico onde o ciphertext está guardado
    private static Map<String, String> hashToBlockId =
            Collections.synchronizedMap(new HashMap<>());

    // Índice para pesquisa "cega": token(keyword-hash) -> conjunto de docIds que têm esse token
    private static Map<String, Set<String>> tokenIndex =
            Collections.synchronizedMap(new HashMap<>());

    // Map docId -> lista ordenada de blockIds (IDs físicos) que compõem o documento
    private static Map<String, List<String>> docToBlocks =
            Collections.synchronizedMap(new HashMap<>());

    // Map blockId -> authTag (tag que o cliente envia; neste projeto é usada pelo cliente para GCM)
    // Nota: em AES-GCM "tag" é intrínseca ao algoritmo; aqui vocês enviam a tag separada e guardam no servidor.
    private static Map<String, byte[]> blockAuthTags =
            Collections.synchronizedMap(new HashMap<>());

    // Estrutura serializável que agrupa os mapas que vocês querem persistir em metadata.enc
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

        // Garante que existe a pasta onde os blocos vão ser guardados
        File dir = new File(BLOCK_DIR);
        if (!dir.exists()) dir.mkdir();

        // Inicialização: carregar chaves/índices/metadados
        try {
            metaKey = getOrCreateKey();        // chave AES local do servidor p/ metadata.enc
            oasPublicKey = loadOasPublicKey(); // chave pública OAS para validar JWT
            loadMetadata();                    // tokenIndex, docToBlocks, blockAuthTags
            loadHashIndex();                   // hashToBlockId (dedup)
        } catch (Exception e) {
            System.err.println("WARN: Falha a inicializar OBSS: " + e.getMessage());
        }

        // Stats só informativas no arranque
        System.out.println("[OBSS Stats]");
        System.out.println(" - Blocos Únicos: " + hashToBlockId.size());
        System.out.println(" - Documentos: " + docToBlocks.size());
        System.out.println(" - Keywords: " + tokenIndex.size());

        // Keystore TLS do servidor (certificado do OBSS)
        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        // Hook: ao terminar o processo, tenta persistir metadados no disco
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nA encerrar OBSS... a guardar metadados.");
            try { saveMetadata(); } catch (Exception e) { e.printStackTrace(); }
        }));

        // Servidor TLS
        try {
            SSLServerSocketFactory sslFactory =
                    (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

            try (SSLServerSocket serverSocket =
                         (SSLServerSocket) sslFactory.createServerSocket(PORT)) {

                // Limita para TLS 1.2 / 1.3
                String[] wanted = Arrays.stream(serverSocket.getEnabledProtocols())
                        .filter(p -> p.equals("TLSv1.3") || p.equals("TLSv1.2"))
                        .toArray(String[]::new);
                if (wanted.length > 0) serverSocket.setEnabledProtocols(wanted);

                System.out.println("Secure BlockStorageServer (TLS) a escutar na porta " + PORT);

                // Loop principal: aceita clientes e cria uma thread por ligação
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
        // Cada cliente comunica por DataInputStream/DataOutputStream
        try (
                DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))
        ) {
            while (true) {
                String command;
                try {
                    command = in.readUTF();
                } catch (EOFException eof) {
                    // cliente fechou
                    break;
                }

                // Dispatch pelos comandos do protocolo OBSS
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
                        // erro simples sem assinatura (OBSS não assina respostas)
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

    // =========================
    // STORE_BLOCK: guarda um bloco (ciphertext) e atualiza índices/metadata
    // =========================
    private static void storeBlock(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // 1) Autorização: cliente envia JWT, servidor valida assinatura do OAS e scopes
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Falta scope obss:share");
            }

            // 2) Leitura do pedido: blockId lógico e hash do plaintext (para dedup)
            String blockId = in.readUTF();        // id “proposto” pelo cliente
            String plaintextHash = in.readUTF();  // SHA-256 do chunk em claro (cliente calcula)

            // 3) Recebe iv+ciphertext (o cliente concatena IV + C)
            int cipherLen = in.readInt();
            if (cipherLen < 0 || cipherLen > MAX_CIPHER_LEN) {
                throw new IOException("Tamanho de cipher inválido: " + cipherLen);
            }
            byte[] ivAndCipher = new byte[cipherLen];
            if (cipherLen > 0) {
                in.readFully(ivAndCipher);
            }

            // 4) Recebe authTag (tag GCM do chunk) separada
            int tagLen = in.readInt();
            if (tagLen < 0 || tagLen > MAX_TAG_LEN) {
                throw new IOException("Tamanho de tag inválido: " + tagLen);
            }
            byte[] authTag = new byte[tagLen];
            if (tagLen > 0) in.readFully(authTag);

            // 5) Metadata: metaCount inclui docId + keywords (apenas no 1º chunk, no cliente)
            int metaCount = in.readInt();
            if (metaCount < 1 || metaCount > MAX_META_COUNT) {
                throw new IOException("metaCount inválido: " + metaCount);
            }

            // Primeiro elemento é docId
            String docId = in.readUTF();

            // Restantes são keywords (já “blind”: hashed token)
            List<String> keywords = new ArrayList<>();
            for (int i = 0; i < metaCount - 1; i++) {
                keywords.add(in.readUTF());
            }

            // 6) Deduplicação:
            // Se plaintextHash já existe, não guardamos novo ficheiro físico.
            // Apenas apontamos doc->block para o bloco físico já existente.
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
                    saveHashIndex(); // persistência do índice de dedup
                }
            }

            // 7) docId -> lista de blocos (ordem de upload)
            synchronized (docToBlocks) {
                docToBlocks
                        .computeIfAbsent(docId, k -> new ArrayList<>())
                        .add(finalPhysicalId);
            }

            // 8) Índice de pesquisa: keywordToken -> docId
            synchronized (tokenIndex) {
                for (String k : keywords) {
                    tokenIndex
                            .computeIfAbsent(k, s -> new HashSet<>())
                            .add(docId);
                }
            }

            // 9) Guardar authTag do bloco (apenas 1 vez por bloco físico)
            synchronized (blockAuthTags) {
                if (!blockAuthTags.containsKey(finalPhysicalId) && tagLen > 0) {
                    blockAuthTags.put(finalPhysicalId, authTag);
                }
            }

            // 10) Se não foi duplicado, escreve o bloco físico para disco
            if (!isDuplicate) {
                File blockFile = new File(BLOCK_DIR, finalPhysicalId);
                try (FileOutputStream fos = new FileOutputStream(blockFile)) {
                    fos.write(ivAndCipher);
                }
            }

            // 11) Persistir metadados (tokenIndex/docToBlocks/blockAuthTags + hashIndex)
            saveMetadata();

            // 12) Responder ao cliente
            out.writeUTF(isDuplicate ? "OK_DUP" : "OK");
            out.flush();

        } catch (GeneralSecurityException e) {
            // Qualquer falha de autenticação/autorização
            System.out.println("Security Error STORE_BLOCK: " + e.getMessage());
            out.writeUTF("ERROR:UNAUTHORIZED");
            out.flush();
        }
    }

    // =========================
    // GET_BLOCK: devolve iv+ciphertext + tag para um blockId
    // =========================
    private static void getBlock(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // 1) Autorização via JWT
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Falta scope obss:get");
            }

            // 2) Identifica bloco físico
            String blockId = in.readUTF();
            File blockFile = new File(BLOCK_DIR, blockId);

            // 3) Se não existe, devolve 0/0 (cliente interpreta como falha/inexistente)
            if (!blockFile.exists()) {
                out.writeInt(0); // cipherLen
                out.writeInt(0); // tagLen
                out.flush();
                return;
            }

            // 4) Lê iv+ciphertext do ficheiro
            byte[] ivAndCipher = new byte[(int) blockFile.length()];
            try (FileInputStream fis = new FileInputStream(blockFile)) {
                int read = fis.read(ivAndCipher);
                if (read != ivAndCipher.length) {
                    throw new IOException("Leitura incompleta do bloco");
                }
            }

            // 5) Obtém a tag associada ao bloco (se existir)
            byte[] tag;
            synchronized (blockAuthTags) {
                tag = blockAuthTags.getOrDefault(blockId, new byte[0]);
            }

            // 6) Envia ao cliente: cipherLen + bytes + tagLen + bytes
            out.writeInt(ivAndCipher.length);
            out.write(ivAndCipher);
            out.writeInt(tag.length);
            out.write(tag);
            out.flush();

        } catch (GeneralSecurityException e) {
            // Em caso de falha de autorização, devolve “vazio” (0/0)
            System.out.println("Security Error GET_BLOCK: " + e.getMessage());
            out.writeInt(0);
            out.writeInt(0);
            out.flush();
        }
    }

    // =========================
    // SEARCH: devolve docIds associados a um token(keyword-hash)
    // =========================
    private static void searchByToken(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // 1) Autorização (scope de search)
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:search")) {
                throw new GeneralSecurityException("Falta scope obss:search");
            }

            // 2) Token pesquisado (já hashed no cliente)
            String searchToken = in.readUTF();

            // 3) Vai ao índice e devolve conjunto de docIds
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
            // Falha de autorização => 0 resultados
            System.out.println("Security Error SEARCH: " + e.getMessage());
            out.writeInt(0);
            out.flush();
        }
    }

    // =========================
    // GET_DOC_BLOCKS: devolve a lista de blockIds (físicos) que compõem um docId
    // =========================
    private static void getDocBlocks(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // 1) Autorização (scope GET)
            String token = in.readUTF();
            JwtUtils.JwtPayload payload = JwtUtils.verifyAndParse(token, oasPublicKey, "OAS");
            if (!hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Falta scope obss:get");
            }

            // 2) DocId pedido
            String docId = in.readUTF();

            // 3) Resposta: nº blocos + lista de blockIds
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
            // Sem autorização => 0 blocos
            System.out.println("Security Error GET_DOC_BLOCKS: " + e.getMessage());
            out.writeInt(0);
            out.flush();
        }
    }

    // Helper: verifica se string de scopes contém um scope específico
    private static boolean hasScope(String scopeStr, String wanted) {
        if (scopeStr == null || scopeStr.isBlank()) return false;
        String[] parts = scopeStr.split("\\s+");
        for (String p : parts) if (p.equalsIgnoreCase(wanted)) return true;
        return false;
    }

    // Carrega a chave pública do OAS a partir do ficheiro do keypair:
    // formato: int pubLen + pubBytes + (depois há privLen+privBytes mas aqui não interessa)
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

    // Cria ou carrega a chave AES usada para cifrar/decifrar metadata.enc (persistência server-side)
    private static SecretKey getOrCreateKey() throws IOException {
        File f = new File(META_KEY_FILE);

        // Se existir, lê bytes Base64 e reconstrói SecretKey AES
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new SecretKeySpec(raw, "AES");
            } catch (Exception e) {
                throw new IOException(e);
            }
        } else {
            // Se não existir, gera AES-256 e guarda em Base64
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

    // Carrega do disco o índice de dedup hash->blockId físico (serialização Java)
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

    // Persiste hashToBlockId para o disco (serialização Java)
    private static void saveHashIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(HASH_INDEX_FILE))) {
            oos.writeObject(hashToBlockId);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Guarda metadados (tokenIndex/docToBlocks/blockAuthTags) cifrados com AES-GCM
    private static void saveMetadata() {
        try {
            // 1) Agrupa mapas num blob serializável
            MetaBlob blob = new MetaBlob(tokenIndex, docToBlocks, blockAuthTags);

            // 2) Serializa para bytes
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();

            // 3) Nonce GCM
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);

            // 4) AES-GCM (confidencialidade + integridade do blob)
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, metaKey, spec);
            byte[] ct = cipher.doFinal(plain);

            // 5) Escreve ficheiro: nonce || ciphertext+tag
            try (FileOutputStream fos = new FileOutputStream(META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }

            // 6) Também persiste o índice de dedup (ficheiro separado)
            saveHashIndex();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Lê metadados do disco (AES-GCM -> desserializa)
    @SuppressWarnings("unchecked")
    private static void loadMetadata() throws IOException {
        File f = new File(META_FILE);
        if (!f.exists()) return;

        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;

            // nonce + ct
            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);

            // Decifra e valida tag GCM
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, metaKey, spec);
            byte[] plain = cipher.doFinal(ct);

            // Desserializa o MetaBlob e restaura os mapas
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
            // Se falhar (ex: chave diferente, ficheiro corrompido, tag inválida), lança IOException
            throw new IOException("Falha metadados: " + e.getMessage());
        }
    }
}
