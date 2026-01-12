import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

public class Project2Client {

    // ======= Endereços/portas dos 3 serviços do projeto =======
    private static final String HOST = "localhost"; // host onde correm os servidores (OAS/OAMS/OBSS)
    private static final int PORT_OAS  = 6000;      // porta do OAS (Oblivious Auth Server)
    private static final int PORT_OAMS = 7000;      // porta do OAMS (Oblivious Access Mgmt Server)
    private static final int PORT_OBSS = 5000;      // porta do OBSS (Oblivious Block Storage Server)

    // ======= Constantes criptográficas =======
    private static final String SIGN_ALGO = "SHA256withECDSA";     // algoritmo de assinatura (ECDSA + SHA-256)
    private static final String FILE_CIPHER = "AES/GCM/NoPadding"; // cifragem dos ficheiros/blocos
    private static final int AES_KEY_SIZE = 256;                   // tamanho da chave AES (bits)
    private static final int GCM_IV_LEN = 12;                      // tamanho do IV/nonce em GCM (bytes)
    private static final int GCM_TAG_LEN = 128;                    // tamanho do tag GCM (bits)

    // ======= Ficheiros locais do cliente =======
    // Onde o cliente guarda a sua identidade (KeyPair EC) serializada
    private static final String USER_KEY_FILE = System.getProperty("p2.userKeyFile", "user.keys");
    // Truststore (certificados CA/servidor) para o TLS do lado do cliente
    private static final String TRUSTSTORE_FILE = "clienttruststore.jks";

    // ======= Chaves públicas dos servidores (para validar assinaturas) =======
    private static PublicKey oasPublicKey;  // usada para validar respostas assinadas do OAS + JWT
    private static PublicKey oamsPublicKey; // usada para validar respostas assinadas do OAMS

    // ======= Estado do utilizador no cliente =======
    private static KeyPair userKeyPair;     // identidade local do utilizador (chave privada + pública)
    private static String userFingerprint;  // fingerprint (SHA-256) da publicKey (identificador do user)
    private static String jwtToken = null;  // JWT emitido pelo OAS após autenticação

    // ======= UI/entropy =======
    private static final Scanner scanner = new Scanner(System.in); // menu interativo
    private static final SecureRandom RNG = new SecureRandom();    // RNG para IVs GCM, etc.

    public static void main(String[] args) {
        try {
            // Configura truststore TLS do cliente
            initTLS();

            // Carrega chaves públicas do OAS e OAMS (para validar assinaturas)
            loadServerKeys();

            // Carrega (se existir) a identidade do utilizador (KeyPair) guardada em disco
            loadIdentity();

            // Menu principal do cliente
            mainMenu();

        } catch (Exception e) {
            System.err.println("Erro Fatal no Cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initTLS() {
        // Define o truststore que o Java TLS vai usar para confiar nos certificados dos servidores
        System.setProperty("javax.net.ssl.trustStore", TRUSTSTORE_FILE);
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    private static void loadServerKeys() {
        try {
            // Estes ficheiros contêm pares de chaves (pub+priv) dos servidores.
            // O cliente só lê a parte pública para verificar assinaturas das respostas.
            oasPublicKey = loadPublicKeyFromFile("oas_signing_keypair.bin");
            oamsPublicKey = loadPublicKeyFromFile("oams_signing_keypair.bin");
            System.out.println("[Init] Chaves públicas dos servidores carregadas.");
        } catch (Exception e) {
            // Se falhar, o cliente ainda funciona mas fica sem validação de assinaturas (inseguro)
            System.out.println("[WARN] Não foi possível carregar chaves dos servidores (Validação de assinatura falhará).");
        }
    }

    private static void mainMenu() throws Exception {
        // Loop do menu até o utilizador escolher Exit
        while (true) {
            System.out.println("\n=========== PROJECT 2 SECURE CLIENT ===========");

            // Mostra estado do utilizador (fingerprint) e estado de autenticação (JWT)
            if (userFingerprint != null) {
                System.out.println("User FP: " + userFingerprint);
                System.out.println("User: " + userFingerprint.substring(0, 8) + "...");
            } else {
                System.out.println("User: Não registado/carregado");
            }
            System.out.println("Auth: " + (jwtToken != null ? "SIM" : "NÃO"));

            // Menu de operações (OAS / OBSS / OAMS)
            System.out.println("\n1. Create Identity & Register (OAS)");
            System.out.println("2. Authenticate (OAS)");
            System.out.println("3. Manage Account (Modify/Delete)");
            System.out.println("-----------------------------------");
            System.out.println("4. Upload File (Encrypted -> OBSS + OAMS)");
            System.out.println("5. Download File (Decrypt <- OBSS + OAMS)");
            System.out.println("6. Search (Blind Search)");
            System.out.println("-----------------------------------");
            System.out.println("7. Share File (OAMS)");
            System.out.println("8. Revoke Share (OAMS)");
            System.out.println("0. Exit");
            System.out.print("Opção: ");

            // Lê a opção do utilizador e chama a função correspondente
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1": createRegistration(); break;
                case "2": authenticate(); break;
                case "3": manageAccount(); break;
                case "4": uploadFile(); break;
                case "5": downloadFile(); break;
                case "6": searchFiles(); break;
                case "7": createShare(); break;
                case "8": deleteShare(); break;
                case "0": return;
                default: System.out.println("Opção inválida.");
            }
        }
    }

    private static void createRegistration() throws Exception {
        System.out.println("\n== CRIAR IDENTIDADE ==");

        // 1) Gera nova identidade EC (P-256) local do utilizador
        userKeyPair = JwtUtils.generateEcKeyPair();

        // 2) Calcula fingerprint para servir como "User ID"
        userFingerprint = JwtUtils.publicKeyFingerprint(userKeyPair.getPublic());

        // 3) Guarda identidade em disco para reutilizar no futuro
        saveIdentity();

        System.out.println("Nova identidade criada.");
        System.out.println("Fingerprint (User FP): " + userFingerprint);

        // PublicKey em bytes para enviar ao OAS
        byte[] pubBytes = userKeyPair.getPublic().getEncoded();

        // Password escolhida pelo utilizador (o OAS vai guardar hash+salt com PBKDF2)
        System.out.print("Escolha uma Password: ");
        String pwd = scanner.nextLine().trim();

        // Atributos opcionais (neste cliente estão vazios)
        Map<String, String> attrs = new HashMap<>();

        // 4) Liga ao OAS por TLS e envia pedido CREATE_REG assinado pela chave privada do user
        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Timestamp para impedir replay (o servidor valida tolerância)
            long timestamp = System.currentTimeMillis();

            // 4.1) Construir bytes exatos do que vamos assinar (mesma ordem do protocolo)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CREATE_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(pwd);
            dos.writeInt(attrs.size()); // aqui 0
            dos.writeLong(timestamp);

            // 4.2) Assina o pedido com a private key do utilizador
            byte[] signature = signData(baos.toByteArray());

            // 4.3) Envia o pedido + assinatura ao servidor
            out.writeUTF("CREATE_REG");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeInt(attrs.size());
            out.writeLong(timestamp);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();

            // 4.4) Lê resposta do OAS e valida assinatura do servidor
            readSignedResponse(in, oasPublicKey);

            System.out.println("Identidade criada e salva em '" + USER_KEY_FILE + "'.");
        }
    }

    private static void authenticate() throws Exception {
        // Só dá para autenticar se existir identidade carregada
        if (userKeyPair == null) {
            System.out.println("Erro: Nenhuma identidade carregada.");
            return;
        }

        // Password para prova de conhecimento (servidor valida PBKDF2)
        System.out.print("Password: ");
        String pwd = scanner.nextLine().trim();

        byte[] pubBytes = userKeyPair.getPublic().getEncoded();

        // ======= Fase 1: AUTH_START (obter nonce/challenge do OAS) =======
        byte[] nonce;
        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Envia AUTH_START com a publicKey do utilizador
            out.writeUTF("AUTH_START");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.flush();

            // O servidor responde "OK" + nonce + assinatura OU erro assinado
            String status = in.readUTF();

            if (!"OK".equals(status)) {
                // Erro: vem com assinatura do OAS
                int sigLen = in.readInt();
                byte[] sig = new byte[sigLen];
                in.readFully(sig);

                // Valida assinatura do servidor no texto de erro
                if (!verifySignature(status.getBytes(StandardCharsets.UTF_8), sig, oasPublicKey)) {
                    System.out.println("ERRO FATAL: Resposta do OAS com assinatura inválida: " + status);
                } else {
                    System.out.println("Servidor OAS: " + status);
                }
                return;
            }

            // Lê nonce enviado pelo OAS
            int nonceLen = in.readInt();
            nonce = new byte[nonceLen];
            in.readFully(nonce);

            // Lê assinatura do OAS sobre (OK + nonce)
            int sigLen = in.readInt();
            byte[] sig = new byte[sigLen];
            in.readFully(sig);

            // Reconstroi exatamente o que o OAS assinou para validar
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("OK");
            dos.writeInt(nonceLen);
            dos.write(nonce);

            // Se assinatura falhar => possível MITM/servidor falso
            if (!verifySignature(baos.toByteArray(), sig, oasPublicKey)) {
                System.out.println("ERRO FATAL: Assinatura do OAS inválida! Possível ataque.");
                return;
            }
        }

        // ======= Fase 2: AUTH_FINISH (provar posse da private key + password) =======
        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Constrói mensagem do desafio:
            // "AUTH|<fingerprint>|<nonceB64>" e assina com a private key do utilizador
            String nonceB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
            String challengeMsg = "AUTH|" + userFingerprint + "|" + nonceB64;
            byte[] signature = signData(challengeMsg.getBytes(StandardCharsets.UTF_8));

            // Envia AUTH_FINISH com pubKey + password + assinatura do desafio
            out.writeUTF("AUTH_FINISH");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();

            // Resposta: "OK" + token + assinatura do OAS OU erro assinado
            String status = in.readUTF();
            if ("OK".equals(status)) {
                String token = in.readUTF();

                int sLen = in.readInt();
                byte[] sig = new byte[sLen];
                in.readFully(sig);

                // Valida assinatura do OAS sobre ("OK" + token)
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeUTF("OK");
                dos.writeUTF(token);

                if (verifySignature(baos.toByteArray(), sig, oasPublicKey)) {
                    jwtToken = token; // guarda JWT para futuras operações
                    System.out.println("Autenticado com sucesso.");
                } else {
                    System.out.println("ERRO: Token recebido com assinatura inválida.");
                }
            } else {
                // Erro assinado
                int sigLen = in.readInt();
                byte[] sig = new byte[sigLen];
                in.readFully(sig);

                if (!verifySignature(status.getBytes(StandardCharsets.UTF_8), sig, oasPublicKey)) {
                    System.out.println("ERRO FATAL: Resposta de erro do OAS com assinatura inválida: " + status);
                } else {
                    System.out.println("OAS: " + status);
                }
            }
        }
    }

    private static void uploadFile() throws Exception {
        // Só permite upload se já houver JWT (login)
        if (jwtToken == null) { System.out.println("Login necessário."); return; }

        // Caminho do ficheiro a enviar
        System.out.print("Caminho do ficheiro: ");
        String path = scanner.nextLine().trim();
        File f = new File(path);
        if (!f.exists()) { System.out.println("Ficheiro não encontrado."); return; }

        // docId identifica o documento lógico (vai mapear para lista de blocos no OBSS)
        String docId = UUID.randomUUID().toString();

        // Keywords (para pesquisa cega): cliente faz hash e o OBSS indexa docId por token
        System.out.print("Keywords (separadas por vírgula): ");
        String kwInput = scanner.nextLine().trim();
        List<String> kws = new ArrayList<>();

        // Transforma keywords em tokens hashed (SHA-256 hex) para “blind search”
        if(!kwInput.isEmpty()) {
            for(String k : kwInput.split(",")) kws.add(hashString(k.trim().toLowerCase()));
        }

        // Gera uma chave AES aleatória para cifrar o ficheiro (por documento)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey fileKey = kg.generateKey();

        // Liga ao OBSS e envia o ficheiro em chunks
        try (SSLSocket socket = connectTLS(PORT_OBSS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream());
             FileInputStream fis = new FileInputStream(f)) {

            // Buffer de 1MB (chunk size)
            byte[] buf = new byte[1024 * 1024];
            int read;
            boolean first = true; // primeiro chunk carrega docId + keywords; restantes só docId

            System.out.println("A encriptar e enviar docID: " + docId);

            while ((read = fis.read(buf)) != -1) {
                // Recorta o buffer ao tamanho real lido
                byte[] chunk = Arrays.copyOf(buf, read);

                // Hash do plaintext do chunk (para dedup no OBSS)
                String plaintextHash = hashBytes(chunk);

                // IV/nonce aleatório para AES-GCM neste chunk
                byte[] iv = new byte[GCM_IV_LEN];
                RNG.nextBytes(iv);

                // Encripta o chunk com AES-GCM (retorna ciphertext + authTag)
                EncryptionResult encResult = encryptAesGcm(chunk, fileKey, iv);

                // Protocolo STORE_BLOCK:
                out.writeUTF("STORE_BLOCK");
                out.writeUTF(jwtToken);                 // JWT para autorizar "share/store"
                out.writeUTF(UUID.randomUUID().toString()); // blockId lógico (pode ser substituído por dedup)
                out.writeUTF(plaintextHash);            // usado pelo servidor para deduplicação

                // Envia iv + ciphertext juntos (para o servidor guardar como bloco físico)
                byte[] ivAndCipher = new byte[iv.length + encResult.ciphertext.length];
                System.arraycopy(iv, 0, ivAndCipher, 0, iv.length);
                System.arraycopy(encResult.ciphertext, 0, ivAndCipher, iv.length, encResult.ciphertext.length);

                out.writeInt(ivAndCipher.length);
                out.write(ivAndCipher);

                // Envia a authTag separadamente
                out.writeInt(encResult.authTag.length);
                out.write(encResult.authTag);

                // Metadados: no 1º chunk envia docId + keywords; nos restantes envia só docId
                if (first) {
                    out.writeInt(kws.size() + 1); // +1 porque docId conta como primeiro elemento
                    out.writeUTF(docId);
                    for (String k : kws) out.writeUTF(k);
                    first = false;
                } else {
                    out.writeInt(1);
                    out.writeUTF(docId);
                }
                out.flush();

                // Lê resposta do OBSS (OK ou OK_DUP)
                String resp = in.readUTF();
                if (!resp.startsWith("OK")) throw new IOException("OBSS Error: " + resp);
            }
        }

        // Depois do upload: “regista” no OAMS a partilha do doc para o próprio dono
        // Aqui vocês guardam a chave do ficheiro (fileKey) como keyBlob no OAMS (não está cifrada neste cliente)
        byte[] wrappedKey = fileKey.getEncoded();
        registerShareInOams(docId, userFingerprint, "GET SEARCH SHARE", wrappedKey);

        System.out.println("Ficheiro guardado com sucesso! DocID: " + docId);
    }

    private static void downloadFile() throws Exception {
        // Só permite download se já houver JWT
        if (jwtToken == null) { System.out.println("Login necessário."); return; }

        System.out.print("DocID: ");
        String docId = scanner.nextLine().trim();

        // 1) Pergunta ao OAMS se tem acesso GET e obtém a chave do documento (keyBlob)
        byte[] keyBlob = checkAccessAndGetKey(docId, "GET");
        if (keyBlob == null || keyBlob.length == 0) {
            System.out.println("Acesso negado ou chave não encontrada.");
            return;
        }

        // 2) Reconstrói SecretKey AES a partir dos bytes guardados no OAMS
        SecretKey fileKey = new SecretKeySpec(keyBlob, "AES");

        // 3) Vai ao OBSS buscar a lista de blocos do doc e depois cada bloco
        try (SSLSocket socket = connectTLS(PORT_OBSS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Pede ao OBSS todos os blocos associados ao docId
            out.writeUTF("GET_DOC_BLOCKS");
            out.writeUTF(jwtToken);
            out.writeUTF(docId);
            out.flush();

            int count = in.readInt();
            if (count <= 0) { System.out.println("Ficheiro vazio ou inexistente."); return; }

            // Guarda o ficheiro reconstruído localmente
            File outFile = new File("downloaded_" + docId + ".bin");

            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                for (int i = 0; i < count; i++) {
                    // Lê blockId (físico) retornado pelo servidor
                    String blockId = in.readUTF();

                    // Pede o bloco
                    out.writeUTF("GET_BLOCK");
                    out.writeUTF(jwtToken);
                    out.writeUTF(blockId);
                    out.flush();

                    // Recebe iv+ciphertext
                    int cipherLen = in.readInt();
                    if (cipherLen <= 0) {
                        System.out.println("Falha ao obter bloco " + blockId +
                                " (possível falta de permissão ou token expirado).");
                        return;
                    }

                    byte[] ivAndCipher = new byte[cipherLen];
                    in.readFully(ivAndCipher);

                    // Recebe tag
                    int tagLen = in.readInt();
                    if (tagLen <= 0) {
                        System.out.println("Falha ao obter tag do bloco " + blockId +
                                " (dados inválidos).");
                        return;
                    }
                    byte[] authTag = new byte[tagLen];
                    in.readFully(authTag);

                    // Separa IV do ciphertext
                    if (cipherLen < GCM_IV_LEN) {
                        throw new IOException("Dados corrompidos (bloco demasiado pequeno).");
                    }
                    byte[] iv = Arrays.copyOfRange(ivAndCipher, 0, GCM_IV_LEN);
                    byte[] ciphertext = Arrays.copyOfRange(ivAndCipher, GCM_IV_LEN, cipherLen);

                    // Decifra chunk e escreve para o ficheiro final
                    byte[] plaintext = decryptAesGcm(ciphertext, authTag, fileKey, iv);
                    fos.write(plaintext);
                }
            }
            System.out.println("Ficheiro decifrado e salvo: " + outFile.getName());
        }
    }

    private static void searchFiles() throws Exception {
        // Só permite search se já houver JWT
        if (jwtToken == null) {
            System.out.println("Login necessário.");
            return;
        }

        // 1) Valida no OAMS que o utilizador tem permissão SEARCH (e scope obss:search)
        // Usa docId = "ANY" como caso especial no OAMS para “search global permitido”
        byte[] res = checkAccessAndGetKey("ANY", "SEARCH");
        if (res == null) {
            System.out.println("Sem permissão para pesquisar (scope obss:search em falta).");
            return;
        }

        // 2) O cliente pede keyword em claro, mas faz hash localmente (blind search)
        System.out.print("Keyword: ");
        String kw = scanner.nextLine().trim().toLowerCase();
        String hashedKw = hashString(kw);

        // 3) Vai ao OBSS pedir docs associados ao token (hash) - ainda sem filtrar ACL
        try (SSLSocket socket = connectTLS(PORT_OBSS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            out.writeUTF("SEARCH");
            out.writeUTF(jwtToken);
            out.writeUTF(hashedKw);
            out.flush();

            int count = in.readInt();
            List<String> docs = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                docs.add(in.readUTF());
            }

            // 4) Filtra resultados confirmando acesso GET no OAMS para cada docId
            System.out.println("Resultados com acesso (após ACL OAMS):");
            int shown = 0;
            for (String docId : docs) {
                byte[] keyBlob = checkAccessAndGetKey(docId, "GET");
                if (keyBlob != null && keyBlob.length > 0) {
                    System.out.println(" - " + docId);
                    shown++;
                }
            }

            if (shown == 0) {
                System.out.println("Nenhum documento acessível para essa keyword.");
            }
        }
    }

    private static void registerShareInOams(String docId, String grantee, String perms, byte[] keyBlob) throws Exception {
        // Cria/atualiza uma entrada de partilha (ACL) no OAMS para (docId, grantee)
        try (SSLSocket socket = connectTLS(PORT_OAMS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();              // anti-replay
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();   // publicKey do requester (para validar assinatura)

            // Constrói os bytes a assinar (protocolo CREATE_SHARE)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CREATE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(grantee);
            dos.writeUTF(perms);
            dos.writeInt(keyBlob.length);
            if (keyBlob.length > 0) dos.write(keyBlob);
            dos.writeLong(timestamp);

            // Assina com private key do user (prova de identidade)
            byte[] sig = signData(baos.toByteArray());

            // Envia pedido + publicKey + assinatura (OAMS valida fingerprint do JWT = fingerprint da pubKey)
            out.writeUTF("CREATE_SHARE");
            out.writeUTF(jwtToken);
            out.writeUTF(docId);
            out.writeUTF(grantee);
            out.writeUTF(perms);
            out.writeInt(keyBlob.length);
            if (keyBlob.length > 0) out.write(keyBlob);
            out.writeLong(timestamp);
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            // Lê resposta assinada pelo OAMS e valida assinatura do servidor
            readSignedResponse(in, oamsPublicKey);
        }
    }

    private static byte[] checkAccessAndGetKey(String docId, String perm) {
        // Pergunta ao OAMS se o utilizador (subject do JWT) tem permissão para docId
        // Se permitido, OAMS devolve keyBlob (chave do ficheiro) para GET (ou vazio no caso SEARCH/ANY)
        try (SSLSocket socket = connectTLS(PORT_OAMS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();             // anti-replay
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();  // publicKey do requester

            // Constrói dados assinados do pedido
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CHECK_ACCESS");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(perm);
            dos.writeLong(timestamp);

            // Assina o pedido com private key do user
            byte[] sig = signData(baos.toByteArray());

            // Envia pedido + publicKey + assinatura
            out.writeUTF("CHECK_ACCESS");
            out.writeUTF(jwtToken);
            out.writeUTF(docId);
            out.writeUTF(perm);
            out.writeLong(timestamp);
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            // Resposta do OAMS:
            // - "OK" + blobLen + blob + assinatura(server)
            // - ou "DENY"/"ERROR:..." + assinatura(server)
            String status = in.readUTF();

            if ("OK".equals(status)) {
                int blobLen = in.readInt();
                byte[] keyBlob = new byte[blobLen];
                if (blobLen > 0) in.readFully(keyBlob);

                // Assinatura do OAMS sobre ("OK" + blobLen + blob)
                int sLen = in.readInt();
                byte[] serverSig = new byte[sLen];
                in.readFully(serverSig);

                // Reconstroi bytes para verificar assinatura
                ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
                DataOutputStream respDos = new DataOutputStream(respBaos);
                respDos.writeUTF(status);
                respDos.writeInt(blobLen);
                if (blobLen > 0) respDos.write(keyBlob);

                // Se assinatura inválida => resposta pode ter sido adulterada
                if (!verifySignature(respBaos.toByteArray(), serverSig, oamsPublicKey)) {
                    System.out.println("ALERTA: Resposta OAMS com assinatura inválida.");
                    return null;
                }

                return keyBlob; // keyBlob pode ser vazio (ex: SEARCH/ANY) ou chave do doc (GET)

            } else {
                // Erro/deny assinado apenas com o texto status
                int sigLen = in.readInt();
                byte[] serverSig = new byte[sigLen];
                in.readFully(serverSig);

                if (!verifySignature(status.getBytes(StandardCharsets.UTF_8), serverSig, oamsPublicKey)) {
                    System.out.println("ALERTA: Resposta OAMS (erro) com assinatura inválida: " + status);
                } else {
                    System.out.println("OAMS: " + status);
                }
                return null;
            }

        } catch (Exception e) {
            System.out.println("Erro CheckAccess: " + e.getMessage());
            return null;
        }
    }

    private static void createShare() throws Exception {
        // Menu para criar uma partilha para outro utilizador (grantee)
        if (jwtToken == null) {
            System.out.println("Login necessário.");
            return;
        }
        if (userKeyPair == null) {
            System.out.println("Nenhuma identidade carregada.");
            return;
        }

        System.out.print("DocID: ");
        String d = scanner.nextLine().trim();
        System.out.print("Grantee FP: ");
        String g = scanner.nextLine().trim();
        System.out.print("Perms (ex: GET SEARCH): ");
        String p = scanner.nextLine().trim();

        // Só partilha se conseguir obter a chave (GET) => prova que tem acesso ao doc
        byte[] keyBlob = checkAccessAndGetKey(d, "GET");
        if (keyBlob == null || keyBlob.length == 0) {
            System.out.println("Não foi possível obter a chave do documento (sem acesso ou doc inexistente).");
            return;
        }

        // Cria entrada ACL no OAMS para o grantee
        registerShareInOams(d, g, p, keyBlob);
        System.out.println("Partilha criada com sucesso para " + g);
    }

    private static void deleteShare() throws Exception {
        // Menu para revogar partilha
        if (jwtToken == null) {
            System.out.println("Login necessário.");
            return;
        }
        if (userKeyPair == null) {
            System.out.println("Nenhuma identidade carregada.");
            return;
        }

        System.out.print("DocID: ");
        String d = scanner.nextLine().trim();
        System.out.print("Grantee FP: ");
        String g = scanner.nextLine().trim();

        // Envia DELETE_SHARE ao OAMS (assinado pelo dono)
        try (SSLSocket socket = connectTLS(PORT_OAMS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();

            // Constrói bytes para assinar (DELETE_SHARE)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(d);
            dos.writeUTF(g);
            dos.writeLong(timestamp);

            byte[] sig = signData(baos.toByteArray());

            // Envia pedido + publicKey + assinatura
            out.writeUTF("DELETE_SHARE");
            out.writeUTF(jwtToken);
            out.writeUTF(d);
            out.writeUTF(g);
            out.writeLong(timestamp);
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            // Lê e valida resposta assinada pelo OAMS
            readSignedResponse(in, oamsPublicKey);
        }
    }

    private static void manageAccount() throws Exception {
        // Menu para gerir registo no OAS (alterar password / apagar conta)
        if (userKeyPair == null) {
            System.out.println("Erro: Nenhuma identidade carregada.");
            return;
        }

        while (true) {
            System.out.println("\n== GESTÃO DE CONTA ==");
            System.out.println("1. Alterar password");
            System.out.println("2. Apagar conta (DELETE_REG)");
            System.out.println("0. Voltar");
            System.out.print("Opção: ");
            String opt = scanner.nextLine().trim();

            if ("0".equals(opt)) return;

            switch (opt) {
                case "1":
                    changePassword();
                    break;
                case "2":
                    deleteAccount();
                    return; // após apagar, sai do menu
                default:
                    System.out.println("Opção inválida.");
            }
        }
    }

    private static void changePassword() throws Exception {
        // Pede password atual + nova e envia MODIFY_REG ao OAS
        System.out.print("Password atual: ");
        String currentPwd = scanner.nextLine().trim();
        System.out.print("Nova password: ");
        String newPwd = scanner.nextLine().trim();

        if (newPwd.isEmpty()) {
            System.out.println("Nova password não pode ser vazia.");
            return;
        }

        byte[] pubBytes = userKeyPair.getPublic().getEncoded();
        long timestamp = System.currentTimeMillis();

        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Constrói bytes assinados do pedido (MODIFY_REG)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("MODIFY_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(currentPwd);
            dos.writeUTF(newPwd);
            dos.writeInt(0);        // attrCount (aqui 0)
            dos.writeLong(timestamp);

            byte[] sig = signData(baos.toByteArray());

            // Envia pedido + assinatura
            out.writeUTF("MODIFY_REG");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(currentPwd);
            out.writeUTF(newPwd);
            out.writeInt(0);
            out.writeLong(timestamp);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            // Resposta assinada pelo OAS
            readSignedResponse(in, oasPublicKey);
        }
    }

    private static void deleteAccount() throws Exception {
        // Apaga o registo no OAS e remove identidade local
        System.out.println("ATENÇÃO: Esta operação vai apagar o registo no OAS.");
        System.out.print("Confirmar (y/n)? ");
        String confirm = scanner.nextLine().trim().toLowerCase();
        if (!confirm.equals("y")) {
            System.out.println("Operação cancelada.");
            return;
        }

        System.out.print("Password: ");
        String pwd = scanner.nextLine().trim();

        byte[] pubBytes = userKeyPair.getPublic().getEncoded();
        long timestamp = System.currentTimeMillis();

        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            // Constrói bytes do pedido DELETE_REG
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(pwd);
            dos.writeLong(timestamp);

            byte[] sig = signData(baos.toByteArray());

            // Envia pedido + assinatura
            out.writeUTF("DELETE_REG");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeLong(timestamp);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            // Resposta assinada pelo OAS
            readSignedResponse(in, oasPublicKey);
        }

        // Limpa estado local e remove ficheiro de identidade
        userKeyPair = null;
        userFingerprint = null;
        jwtToken = null;
        new File(USER_KEY_FILE).delete();
        System.out.println("Identidade local removida. Vai precisar de criar nova identidade.");
    }

    // ======= Assina dados com a private key do utilizador (ECDSA) =======
    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(userKeyPair.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    // ======= Verifica assinatura ECDSA com uma publicKey (servidor ou user) =======
    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey key) {
        try {
            Signature sig = Signature.getInstance(SIGN_ALGO);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) { return false; }
    }

    // Estrutura auxiliar para devolver ciphertext + tag separadamente (porque o Java devolve tudo junto)
    private static class EncryptionResult {
        byte[] ciphertext; // dados cifrados
        byte[] authTag;    // tag de autenticação (GCM)
        EncryptionResult(byte[] c, byte[] t) { ciphertext = c; authTag = t; }
    }

    // ======= Encriptação AES-GCM: devolve ciphertext e tag separados =======
    private static EncryptionResult encryptAesGcm(byte[] plaintext, SecretKey key, byte[] iv)
            throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(FILE_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));

        // output = ciphertext || tag (o provider do Java concatena)
        byte[] output = cipher.doFinal(plaintext);

        int tagBytes = GCM_TAG_LEN / 8;
        byte[] cText = Arrays.copyOfRange(output, 0, output.length - tagBytes);
        byte[] tag = Arrays.copyOfRange(output, output.length - tagBytes, output.length);
        return new EncryptionResult(cText, tag);
    }

    // ======= Desencriptação AES-GCM: recebe ciphertext + tag separados e reconcatena =======
    private static byte[] decryptAesGcm(byte[] ciphertext, byte[] tag, SecretKey key, byte[] iv)
            throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance(FILE_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));

        // input = ciphertext || tag (formato que o Java espera)
        byte[] input = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
        System.arraycopy(tag, 0, input, ciphertext.length, tag.length);

        // Se tag não bater => lança AEADBadTagException (integridade falhou)
        return cipher.doFinal(input);
    }

    // Guarda a identidade local (KeyPair) para disco via serialização Java
    private static void saveIdentity() throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USER_KEY_FILE))) {
            oos.writeObject(userKeyPair);
        }
        System.out.println("Identidade guardada em disco.");
    }

    // Carrega a identidade local (KeyPair) se existir (e atualiza fingerprint)
    private static void loadIdentity() {
        File f = new File(USER_KEY_FILE);
        if (!f.exists()) return;

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            userKeyPair = (KeyPair) ois.readObject();
            userFingerprint = JwtUtils.publicKeyFingerprint(userKeyPair.getPublic());

            System.out.println("Identidade carregada.");
            System.out.println("Fingerprint (User FP): " + userFingerprint);
            System.out.println("User curto: " + userFingerprint.substring(0, 8) + "...");

        } catch (Exception e) {
            System.out.println("Erro ao carregar identidade: " + e.getMessage());
        }
    }

    // Lê um ficheiro de keypair (formato: int len + pubBytes...) e devolve PublicKey EC
    private static PublicKey loadPublicKeyFromFile(String path) throws Exception {
        try (DataInputStream in = new DataInputStream(new FileInputStream(path))) {
            int len = in.readInt();
            byte[] b = new byte[len];
            in.readFully(b);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(b));
        }
    }

    // Hash helper: string -> SHA-256 hex (usado para blind-search tokens)
    private static String hashString(String input) {
        return hashBytes(input.getBytes(StandardCharsets.UTF_8));
    }

    // Hash helper: bytes -> SHA-256 hex (usado para dedup por chunk e para tokens)
    private static String hashBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input);

            StringBuilder sb = new StringBuilder();
            for(byte b: d) sb.append(String.format("%02x", b));
            return sb.toString();

        } catch(Exception e) { return ""; }
    }

    // Lê uma resposta do servidor no formato: UTF msg + int sigLen + sigBytes
    // e valida assinatura com a publicKey do servidor
    private static void readSignedResponse(DataInputStream in, PublicKey serverKey) throws IOException {
        String msg = in.readUTF();
        int len = in.readInt();
        byte[] sig = new byte[len];
        in.readFully(sig);

        // Importante: aqui vocês validam apenas "msg" como bytes UTF-8.
        // (No OAMS há casos onde o servidor assina "OK + blob", e aí vocês reconstroem manualmente noutro método.)
        if (!verifySignature(msg.getBytes(StandardCharsets.UTF_8), sig, serverKey)) {
            throw new IOException("Assinatura do servidor INVALIDA na resposta: " + msg);
        }
        System.out.println("Servidor: " + msg + " (Assinatura Validada)");
    }

    // Cria uma ligação TLS ao HOST:port usando o truststore configurado em initTLS()
    private static SSLSocket connectTLS(int port) throws IOException {
        SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        return (SSLSocket) sslFactory.createSocket(HOST, port);
    }
}
