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

    // Lê a config de criptografia (cipher, keysize, etc.) do ficheiro cryptoconfig.txt.
    // (Aqui, tal como noutros ficheiros, pode não ser usada diretamente, mas força a validação.)
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));

    // Porta do OAMS (Oblivious Access Management Server): gere ACLs / partilhas
    private static final int PORT = 7000;

    // Ficheiros persistentes do OAMS:
    // - ACL_META_FILE: ACLs serializadas e cifradas (AES-GCM)
    // - ACL_META_KEY_FILE: chave AES que cifra/decifra o ACL_META_FILE
    // - OAS_SIGNING_KEYPAIR_FILE: ficheiro com a chave pública do OAS (para validar JWT)
    // - OAMS_SIGNING_KEYPAIR_FILE: chave do próprio OAMS (para assinar respostas ao cliente)
    private static final String ACL_META_FILE = "oams_acls.enc";
    private static final String ACL_META_KEY_FILE = "oams_meta_key.bin";
    private static final String OAS_SIGNING_KEYPAIR_FILE = "oas_signing_keypair.bin";
    private static final String OAMS_SIGNING_KEYPAIR_FILE = "oams_signing_keypair.bin";

    // Config de cifragem dos metadados (ACLs) no disco
    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    // Algoritmo de assinatura ECDSA (P-256 + SHA-256)
    private static final String SIGN_ALGO = "SHA256withECDSA";

    // Anti-replay: tolerância para timestamp nos pedidos assinados pelos clientes
    private static final long TIMESTAMP_TOLERANCE_MS = 300_000; // 5 min

    // RNG para nonces/IVs (AES-GCM)
    private static final SecureRandom RNG = new SecureRandom();

    // ============
    // MODELO ACL
    // ============

    // Entrada de ACL: “owner” partilha docId com “grantee” com permissões e com a chave do ficheiro.
    // Nota: o nome encryptedKeyBlob sugere que a chave do ficheiro devia ir cifrada para o grantee,
    // mas neste código ela é enviada/armazenada como "byte[] keyBlob" e não é cifrada aqui.
    public static class AccessEntry implements java.io.Serializable {
        public String docId;              // identificador do documento
        public String ownerFingerprint;   // fingerprint (ID) de quem é dono
        public String granteeFingerprint; // fingerprint (ID) de quem recebe acesso
        public String permissions;        // ex: "GET SEARCH" / "GET" / etc.
        public byte[] encryptedKeyBlob;   // blob com a chave do doc (normalmente seria “wrapped”/cifrada)

        public AccessEntry(String docId, String ownerFingerprint, String granteeFingerprint,
                           String permissions, byte[] encryptedKeyBlob) {
            this.docId = docId;
            this.ownerFingerprint = ownerFingerprint;
            this.granteeFingerprint = granteeFingerprint;
            this.permissions = permissions;
            this.encryptedKeyBlob = encryptedKeyBlob;
        }
    }

    // Objeto “blob” serializável para persistência: map docId -> lista de entradas ACL
    public static class AclMetaBlob implements java.io.Serializable {
        public Map<String, List<AccessEntry>> aclByDoc;
        public AclMetaBlob(Map<String, List<AccessEntry>> aclByDoc) {
            this.aclByDoc = aclByDoc;
        }
    }

    // Map principal em memória: docId -> lista de AccessEntry
    // synchronizedMap + synchronized blocks nalguns pontos para thread-safety.
    private static Map<String, List<AccessEntry>> aclByDoc =
            Collections.synchronizedMap(new HashMap<>());

    // Chave AES para cifrar/decifrar o ficheiro de ACLs
    private static SecretKey aclMetaKey;

    // Chave pública do OAS: usada para validar JWTs emitidos pelo OAS
    private static PublicKey oasPublicKey;

    // Private key do OAMS: usada para assinar respostas do OAMS aos clientes
    private static PrivateKey oamsPrivateKey;

    public static void main(String[] args) {
        try {
            // 1) Meta-key (AES) para persistência do ACL_META_FILE
            aclMetaKey = getOrCreateMetaKey();

            // 2) Carregar ACLs do disco (AES-GCM -> desserializa)
            loadAclMetadata();

            // 3) Carregar chave pública do OAS para verificar JWTs
            oasPublicKey = loadOasPublicKey();

            // 4) Garantir par de chaves do OAMS (assinar respostas)
            KeyPair oamsKp = getOrCreateSigningKeyPair();
            oamsPrivateKey = oamsKp.getPrivate();

            System.out.println("OAMS iniciado: docIds com ACLs = " + aclByDoc.size());
        } catch (Exception e) {
            System.err.println("Falha a inicializar OAMS: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // Config do keystore TLS do servidor (certificado do servidor)
        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        try {
            // Cria server socket TLS na porta do OAMS
            SSLServerSocketFactory sslFactory =
                    (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

            try (SSLServerSocket serverSocket = (SSLServerSocket) sslFactory.createServerSocket(PORT)) {
                // Limita protocolos a TLSv1.2 e TLSv1.3
                String[] enabled = serverSocket.getEnabledProtocols();
                serverSocket.setEnabledProtocols(Arrays.stream(enabled)
                        .filter(p -> p.equals("TLSv1.2") || p.equals("TLSv1.3"))
                        .toArray(String[]::new));

                System.out.println("ObliviousAccessServer (OAMS) a escutar em TLS na porta " + PORT);

                // Loop principal: aceitar clientes e criar uma thread por ligação
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
        // Cada cliente envia comandos via DataInputStream/DataOutputStream
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {

            while (true) {
                String cmd;
                try {
                    cmd = in.readUTF();
                } catch (EOFException eof) {
                    // cliente fechou a ligação
                    break;
                }

                // Dispatch por comando
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
                        // Resposta assinada do OAMS (autenticidade)
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

    // =========================
    // CREATE_SHARE: cria/atualiza uma entrada ACL
    // =========================
    private static void handleCreateShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe dados do pedido
            String jwtToken = in.readUTF();       // JWT emitido pelo OAS
            String docId = in.readUTF();          // doc a partilhar
            String granteeFp = in.readUTF();      // fingerprint do destinatário
            String permissions = in.readUTF();    // permissões a conceder

            // “key blob” associado ao doc (tipicamente a chave do ficheiro/DEK)
            int keyBlobLen = in.readInt();
            byte[] keyBlob = new byte[keyBlobLen];
            if (keyBlobLen > 0) in.readFully(keyBlob);

            // Proteção anti-replay e prova de posse da chave do subject:
            long timestamp = in.readLong();

            // Cliente envia a sua public key (bytes) para o servidor ligar “assinatura” ao subject
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);

            // Assinatura do cliente sobre os campos do pedido (inclui timestamp)
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Valida JWT (assinatura do OAS) e extrai subject (fingerprint do owner)
            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String ownerFp = payload.subject;

            // Verifica se o JWT tem o scope necessário para gestão de partilhas
            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Token sem scope obss:share");
            }

            // Reconstroi bytes exatamente como o cliente os assinou
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

            // Verifica:
            // 1) timestamp dentro da janela anti-replay
            // 2) clientPubKey corresponde ao subject do JWT (fingerprint)
            // 3) assinatura ECDSA do cliente sobre os bytes do pedido
            validateRequestSignature(ownerFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            // Cria/atualiza a entrada ACL (docId, owner -> grantee)
            AccessEntry entry =
                    new AccessEntry(docId, ownerFp, granteeFp, permissions, keyBlob);

            synchronized (aclByDoc) {
                // 1) obtém lista ACL do doc (ou cria)
                // 2) remove entrada anterior para o mesmo (owner, grantee)
                // 3) adiciona a nova entrada (update)
                List<AccessEntry> list =
                        aclByDoc.computeIfAbsent(docId, k -> new ArrayList<>());
                list.removeIf(e ->
                        e.ownerFingerprint.equals(ownerFp) &&
                        e.granteeFingerprint.equals(granteeFp));
                list.add(entry);
            }

            // Persistir ACLs (AES-GCM)
            saveAclMetadata();

            System.out.println("CREATE_SHARE: OK " +
                    ownerFp.substring(0, 8) + " -> " + granteeFp.substring(0, 8));

            // Resposta assinada pelo OAMS
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            System.err.println("CREATE_SHARE error: " + e.getMessage());
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // DELETE_SHARE: revoga uma entrada ACL
    // =========================
    private static void handleDeleteShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Campos do pedido
            String jwtToken = in.readUTF();
            String docId = in.readUTF();
            String granteeFp = in.readUTF();

            // Proteção anti-replay + assinatura do cliente
            long timestamp = in.readLong();
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);

            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Valida JWT do OAS e obtém owner
            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String ownerFp = payload.subject;

            // Scope necessário para partilhar/revogar
            if (!hasScope(payload.scope, "obss:share")) {
                throw new GeneralSecurityException("Token sem scope obss:share");
            }

            // Reconstroi bytes assinados pelo cliente
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(granteeFp);
            dos.writeLong(timestamp);

            // Verifica timestamp + fingerprint + assinatura do cliente
            validateRequestSignature(ownerFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            // Remove entrada ACL (owner -> grantee) para aquele doc
            boolean removed;
            synchronized (aclByDoc) {
                List<AccessEntry> list = aclByDoc.get(docId);
                if (list != null) {
                    removed = list.removeIf(e ->
                            e.ownerFingerprint.equals(ownerFp) &&
                            e.granteeFingerprint.equals(granteeFp));

                    // Se ficar vazio, remove o docId do map (limpeza)
                    if (list.isEmpty()) aclByDoc.remove(docId);
                } else {
                    removed = false;
                }
            }

            // Resposta conforme encontrou/removou ou não
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

    // =========================
    // CHECK_ACCESS: valida se subject pode GET/SEARCH e devolve keyBlob se aplicável
    // =========================
    private static void handleCheckAccess(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Pedido
            String jwtToken = in.readUTF();
            String docId = in.readUTF();

            // Pode vir "GET", "SEARCH" ou "GET SEARCH" etc.
            String requestedPermRaw = in.readUTF();
            String requestedPerm = requestedPermRaw.toUpperCase(Locale.ROOT).trim();

            // Anti-replay + assinatura do cliente
            long timestamp = in.readLong();
            int pubKeyLen = in.readInt();
            byte[] clientPubKeyBytes = new byte[pubKeyLen];
            in.readFully(clientPubKeyBytes);

            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Valida JWT emitido pelo OAS
            JwtUtils.JwtPayload payload =
                    JwtUtils.verifyAndParse(jwtToken, oasPublicKey, "OAS");
            String subjectFp = payload.subject; // fingerprint do user a pedir acesso

            // Reconstroi bytes assinados pelo cliente
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CHECK_ACCESS");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(requestedPermRaw);
            dos.writeLong(timestamp);

            // Verifica: timestamp + fingerprint + assinatura
            validateRequestSignature(subjectFp, clientPubKeyBytes, baos.toByteArray(),
                    signature, timestamp);

            // Interpreta permissões pedidas
            boolean wantsSearch = requestedPerm.contains("SEARCH");
            boolean wantsGet = requestedPerm.contains("GET");

            // “Scopes” do JWT: mesmo que ACL permita, o JWT precisa de scope correto
            if (wantsSearch && !hasScope(payload.scope, "obss:search")) {
                throw new GeneralSecurityException("Token sem scope obss:search");
            }
            if (wantsGet && !hasScope(payload.scope, "obss:get")) {
                throw new GeneralSecurityException("Token sem scope obss:get");
            }

            // Por default, não devolve chave e nega
            byte[] keyBlobToSend = new byte[0];
            boolean allowed = false;

            // Caso especial: docId = "ANY" e pedido SEARCH => serve só para autorizar pesquisar
            // (não depende de ACL de um documento específico)
            if (docId.equals("ANY") && wantsSearch) {
                allowed = true;
            } else {
                // Caso normal: verificar ACL do docId
                synchronized (aclByDoc) {
                    List<AccessEntry> list = aclByDoc.get(docId);
                    if (list != null) {
                        for (AccessEntry e : list) {

                            // Pode aceder se for owner OU grantee nessa ACL
                            if (e.ownerFingerprint.equals(subjectFp)
                                    || e.granteeFingerprint.equals(subjectFp)) {

                                // Permissões na ACL
                                boolean aclHasGet = permContains(e.permissions, "GET");
                                boolean aclHasSearch = permContains(e.permissions, "SEARCH");

                                // Se pedimos GET, ACL tem de ter GET; se pedimos SEARCH, ACL tem de ter SEARCH
                                boolean okAcl =
                                        (!wantsGet || aclHasGet) &&
                                        (!wantsSearch || aclHasSearch);

                                if (okAcl) {
                                    allowed = true;

                                    // Se existir key blob associado, devolve-o (para GET / decrypt)
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
                // Resposta “OK” + blob + assinatura do OAMS (para o cliente validar autenticidade)
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
                // Negado (assinada)
                sendSignedResponse(out, "DENY");
            }

        } catch (Exception e) {
            System.err.println("CHECK_ACCESS error: " + e.getMessage());
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // Validação do pedido assinado pelo cliente
    // =========================
    private static void validateRequestSignature(
            String jwtSubjectFp,
            byte[] clientPubKeyBytes,
            byte[] signedData,
            byte[] signature,
            long timestamp
    ) throws GeneralSecurityException {

        // 1) Anti-replay por timestamp
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_MS) {
            throw new GeneralSecurityException("Timestamp expirado ou inválido (Replay?)");
        }

        // 2) Reconstrói PublicKey EC do cliente
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey clientPubKey = kf.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));

        // 3) Confirma que a public key apresentada “bate certo” com o subject do JWT
        // (impede alguém usar um JWT de outra pessoa e assinar com outra chave)
        String calculatedFp = JwtUtils.publicKeyFingerprint(clientPubKey);
        if (!calculatedFp.equals(jwtSubjectFp)) {
            throw new GeneralSecurityException("Chave pública não corresponde ao subject do JWT");
        }

        // 4) Verifica assinatura ECDSA do cliente sobre os bytes do pedido
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initVerify(clientPubKey);
        sig.update(signedData);
        if (!sig.verify(signature)) {
            throw new GeneralSecurityException("Assinatura do pedido inválida");
        }
    }

    // Envia uma resposta assinada pelo OAMS:
    // formato: UTF(msg) + int(sigLen) + bytes(sig)
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

    // Assina bytes com a private key do OAMS
    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(oamsPrivateKey);
        sig.update(data);
        return sig.sign();
    }

    // Garante que o OAMS tem um par de chaves EC (para assinar respostas)
    private static KeyPair getOrCreateSigningKeyPair() throws IOException, GeneralSecurityException {
        File f = new File(OAMS_SIGNING_KEYPAIR_FILE);

        // Se existe, lê e reconstrói KeyPair
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
            // Se não existe, gera e guarda em ficheiro
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

    // Verifica se o scope do JWT inclui uma permissão (ex: "obss:get")
    private static boolean hasScope(String scopeStr, String wanted) {
        if (scopeStr == null || scopeStr.isBlank()) return false;
        String[] parts = scopeStr.split("\\s+");
        for (String p : parts) {
            if (p.equalsIgnoreCase(wanted)) return true;
        }
        return false;
    }

    // Verifica se uma string de permissões (ex: "GET SEARCH") contém "GET" ou "SEARCH"
    private static boolean permContains(String perms, String wanted) {
        if (perms == null) return false;
        String[] parts = perms.split("[,\\s]+");
        for (String p : parts) {
            if (p.equalsIgnoreCase(wanted)) return true;
        }
        return false;
    }

    // =========================
    // Persistência: chave AES do ACL_META_FILE
    // =========================
    private static SecretKey getOrCreateMetaKey() throws IOException {
        File f = new File(ACL_META_KEY_FILE);

        // Se existe, lê e reconstrói SecretKey (guardada em Base64)
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new javax.crypto.spec.SecretKeySpec(raw, "AES");
            }
        } else {
            // Se não existe, gera chave AES e guarda em Base64
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

    // Guarda aclByDoc cifrado em AES-GCM: nonce || ciphertext+tag
    private static void saveAclMetadata() {
        try {
            // Serializa o map numa estrutura “blob”
            AclMetaBlob blob = new AclMetaBlob(aclByDoc);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();

            // Nonce GCM
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);

            // AES-GCM (confidencialidade + integridade)
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, aclMetaKey,
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain);

            // Escreve ficheiro: nonce || ct
            try (FileOutputStream fos = new FileOutputStream(ACL_META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Carrega aclByDoc do disco (AES-GCM -> desserializa)
    @SuppressWarnings("unchecked")
    private static void loadAclMetadata() throws IOException {
        File f = new File(ACL_META_FILE);
        if (!f.exists()) return;

        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;

            // nonce + ciphertext
            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);

            // Decifra e valida tag (se falhar, exception)
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, aclMetaKey,
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plain = cipher.doFinal(ct);

            // Desserializa e substitui o map em memória
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

    // Carrega a public key do OAS (ficheiro contém pubLen + pubBytes no início)
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
