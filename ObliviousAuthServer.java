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

    // Lê a configuração criptográfica (cipher, keysize, etc.) do cryptoconfig.txt.
    // (Nota: neste ficheiro específico, a CONFIG não é usada diretamente, mas “força”
    // a leitura/validação da config ao arrancar o servidor.)
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));

    // Porta onde o OAS (Oblivious Authentication Server) vai escutar em TLS
    private static final int PORT = 6000;

    // Ficheiros persistentes do OAS:
    // - USERS_META_FILE: base de dados “de utilizadores” (serializada) mas cifrada em AES-GCM
    // - USERS_META_KEY_FILE: chave simétrica usada para cifrar/decifrar o USERS_META_FILE
    // - SIGNING_KEY_FILE: par de chaves EC (pub+priv) usado para assinar respostas e assinar JWTs
    private static final String USERS_META_FILE = "oas_users.enc";
    private static final String USERS_META_KEY_FILE = "oas_users_meta_key.bin";
    private static final String SIGNING_KEY_FILE = "oas_signing_keypair.bin";

    // Config de cifragem para metadados do servidor (users DB)
    private static final String META_CIPHER = "AES/GCM/NoPadding";
    private static final int META_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    // Algoritmo de assinatura ECDSA (P-256 + SHA-256)
    private static final String SIGN_ALGO = "SHA256withECDSA";

    // Tolerância de tempo para prevenir replay (cliente envia timestamp + assinatura)
    private static final long TIMESTAMP_TOLERANCE_MS = 300_000; // 5 min

    // TTL do JWT emitido após autenticação
    private static final long TOKEN_TTL_SECONDS = 300; // 5 min

    // Gerador de aleatoriedade segura
    private static final SecureRandom RNG = new SecureRandom();

    // Registo de utilizador guardado no “DB” do OAS
    private static class UserRecord implements java.io.Serializable {
        byte[]  publicKeyEncoded;     // public key do utilizador (formato X.509 encoded)
        String  pubKeyFingerprint;    // fingerprint (SHA-256 hex) da public key => ID do user
        byte[]  pwdSalt;              // salt para PBKDF2
        byte[]  pwdHash;              // hash derivado (PBKDF2) da password
        Map<String, String> attributes; // atributos opcionais do utilizador

        UserRecord(byte[] publicKeyEncoded, String pubKeyFingerprint, byte[] pwdSalt, byte[] pwdHash, Map<String, String> attributes) {
            this.publicKeyEncoded = publicKeyEncoded;
            this.pubKeyFingerprint = pubKeyFingerprint;
            this.pwdSalt = pwdSalt;
            this.pwdHash = pwdHash;
            this.attributes = (attributes != null) ? attributes : new HashMap<>();
        }
    }

    // “Blob” serializável para escrever/ler os metadados do OAS num só objeto
    private static class UsersMetaBlob implements java.io.Serializable {
        Map<String, UserRecord> users; // chave: fingerprint -> valor: UserRecord
        UsersMetaBlob(Map<String, UserRecord> users) { this.users = users; }
    }

    // Estruturas em memória (thread-safe via synchronizedMap / synchronized blocks):
    private static Map<String, UserRecord> users = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, byte[]> activeNonces = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, Long> issuedTokens = Collections.synchronizedMap(new HashMap<>());

    // Chave simétrica para cifrar/decifrar a “DB” de utilizadores
    private static SecretKey usersMetaKey;

    // Par de chaves do OAS (ECDSA) para:
    // - assinar respostas do OAS
    // - assinar JWTs emitidos pelo OAS
    private static KeyPair signingKeyPair;

    public static void main(String[] args) {
        try {
            // 1) Garantir chave simétrica para metadados (AES)
            usersMetaKey = getOrCreateMetaKey();

            // 2) Ler “DB” (users) do disco, decifrar e carregar para memória
            loadUsersMetadata();

            // 3) Garantir par de chaves de assinatura do OAS (ECDSA)
            signingKeyPair = getOrCreateSigningKeyPair();
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Falha a inicializar OAS: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        System.out.println("OAS iniciado: utilizadores carregados = " + users.size());

        // Config do keystore TLS do servidor (certificado do servidor)
        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        try {
            // Cria server socket TLS (SSLServerSocket) na porta do OAS
            SSLServerSocketFactory sslFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslFactory.createServerSocket(PORT)) {

                // Limita protocolos a TLSv1.2 e TLSv1.3
                String[] enabled = serverSocket.getEnabledProtocols();
                serverSocket.setEnabledProtocols(Arrays.stream(enabled)
                        .filter(p -> p.equals("TLSv1.2") || p.equals("TLSv1.3"))
                        .toArray(String[]::new));

                System.out.println("ObliviousAuthServer (OAS) a escutar em TLS na porta " + PORT);

                // Thread “garbage collector” de tokens (remove jtis expirados)
                new Thread(ObliviousAuthServer::cleanupExpiredTokens).start();

                // Loop principal: aceitar clientes e criar thread por ligação
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
        // Um cliente liga-se e envia comandos (strings) via DataInputStream/DataOutputStream
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
             DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))) {

            while (true) {
                String cmd;
                try {
                    // Cada comando é um UTF enviado pelo cliente
                    cmd = in.readUTF();
                } catch (EOFException eof) {
                    // Ligação fechada
                    break;
                }

                // Dispatch por comando
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
                        // Erro: comando desconhecido (resposta assinada)
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

    // =========================
    // 1) REGISTO: CREATE_REG
    // =========================
    private static void handleCreateRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe public key do cliente (bytes)
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            // Recebe password (em texto) - o servidor vai armazenar apenas PBKDF2(salt)
            String password = in.readUTF();

            // Recebe atributos (key/value)
            int attrCount = in.readInt();
            Map<String, String> attrs = new HashMap<>();
            for (int i = 0; i < attrCount; i++) {
                attrs.put(in.readUTF(), in.readUTF());
            }

            // Recebe timestamp + assinatura do pedido
            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Reconstroi exatamente os bytes que o cliente assinou
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

            // Verifica (1) timestamp dentro da janela (anti-replay)
            // e (2) assinatura ECDSA feita com a private key correspondente a pubBytes
            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            // Converte pubBytes para PublicKey e calcula fingerprint (SHA-256 hex)
            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                // Se fingerprint já existe => já registado
                if (users.containsKey(fingerprint)) {
                    sendSignedResponse(out, "ERROR:ALREADY_REGISTERED");
                    return;
                }

                // Gera salt e deriva hash PBKDF2
                byte[] salt = new byte[16];
                RNG.nextBytes(salt);

                // PBKDF2 com 200k iterações, output 32 bytes (256 bits)
                byte[] hash = pbkdf2(password.toCharArray(), salt, 200_000, 32);

                // Cria registo e coloca na “DB” em memória
                UserRecord rec = new UserRecord(pubBytes, fingerprint, salt, hash, attrs);
                users.put(fingerprint, rec);
            }

            // Persiste a “DB” de users cifrada
            saveUsersMetadata();

            System.out.println("Registo criado: " + fingerprint.substring(0, 8));
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            // Sempre responde com mensagem assinada (para o cliente validar autenticidade)
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // 2) REGISTO: MODIFY_REG
    // =========================
    private static void handleModifyRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe public key
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            // Recebe password atual e nova password
            String currentPwd = in.readUTF();
            String newPwd = in.readUTF();

            // Recebe atributos novos
            int attrCount = in.readInt();
            Map<String, String> newAttrs = new HashMap<>();
            for (int i = 0; i < attrCount; i++) {
                newAttrs.put(in.readUTF(), in.readUTF());
            }

            // Recebe timestamp + assinatura do pedido
            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Reconstrói bytes assinados
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

            // Verifica assinatura + anti-replay
            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            // Identifica user pelo fingerprint da public key
            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                UserRecord rec = users.get(fingerprint);
                if (rec == null) {
                    sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                    return;
                }

                // Verifica password atual (PBKDF2 com salt guardado)
                byte[] checkHash = pbkdf2(currentPwd.toCharArray(), rec.pwdSalt, 200_000, 32);
                if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                    sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                    return;
                }

                // Se foi fornecida nova password, atualiza salt+hash
                if (newPwd != null && !newPwd.isBlank()) {
                    byte[] newSalt = new byte[16];
                    RNG.nextBytes(newSalt);
                    byte[] newHash = pbkdf2(newPwd.toCharArray(), newSalt, 200_000, 32);
                    rec.pwdSalt = newSalt;
                    rec.pwdHash = newHash;
                }

                // Atualiza atributos
                rec.attributes = newAttrs;
            }

            // Persiste mudanças
            saveUsersMetadata();
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // 3) REGISTO: DELETE_REG
    // =========================
    private static void handleDeleteRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe public key
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            // Recebe password
            String password = in.readUTF();

            // Recebe timestamp + assinatura
            long timestamp = in.readLong();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Reconstrói bytes assinados
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_REG");
            dos.writeInt(pubLen);
            dos.write(pubBytes);
            dos.writeUTF(password);
            dos.writeLong(timestamp);

            // Verifica assinatura + anti-replay
            validateRequestSignature(pubBytes, baos.toByteArray(), signature, timestamp);

            // Calcula fingerprint
            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            synchronized (users) {
                UserRecord rec = users.get(fingerprint);
                if (rec == null) {
                    sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                    return;
                }

                // Confirma password
                byte[] checkHash = pbkdf2(password.toCharArray(), rec.pwdSalt, 200_000, 32);
                if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                    sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                    return;
                }

                // Remove user e também remove nonce ativo (se existia)
                users.remove(fingerprint);
                activeNonces.remove(fingerprint);
            }

            // Persistir
            saveUsersMetadata();
            sendSignedResponse(out, "OK");

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // 4) AUTH: AUTH_START (challenge)
    // =========================
    private static void handleAuthStart(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe public key do cliente
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            // Calcula fingerprint e verifica se existe user registado
            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);

            if (!users.containsKey(fingerprint)) {
                sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                return;
            }

            // Gera nonce aleatório e guarda como “desafio ativo” para aquele user
            byte[] nonce = new byte[32];
            RNG.nextBytes(nonce);
            activeNonces.put(fingerprint, nonce);

            // Resposta do protocolo: "OK" + nonce + assinatura do OAS sobre (OK+nonce)
            out.writeUTF("OK");
            out.writeInt(nonce.length);
            out.write(nonce);

            // Reconstrói bytes a assinar (para o cliente validar autenticidade do desafio)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("OK");
            dos.writeInt(nonce.length);
            dos.write(nonce);

            // Assina com a private key do OAS
            byte[] sig = signData(baos.toByteArray());

            // Envia assinatura
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

        } catch (Exception e) {
            sendSignedResponse(out, "ERROR:" + e.getMessage());
        }
    }

    // =========================
    // 5) AUTH: AUTH_FINISH (resposta ao challenge + emissão JWT)
    // =========================
    private static void handleAuthFinish(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            // Recebe public key
            int pubLen = in.readInt();
            if (pubLen <= 0 || pubLen > 8192) throw new IOException("PubLen inválido");
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            // Recebe password e assinatura do cliente sobre o challenge
            String password = in.readUTF();
            int sigLen = in.readInt();
            byte[] signature = new byte[sigLen];
            in.readFully(signature);

            // Identifica utilizador
            PublicKey pk = decodeEcPublicKey(pubBytes);
            String fingerprint = JwtUtils.publicKeyFingerprint(pk);
            UserRecord rec = users.get(fingerprint);

            if (rec == null) {
                sendSignedResponse(out, "ERROR:NOT_REGISTERED");
                return;
            }

            // Vai buscar (e remover) o nonce ativo daquele user.
            // Remover aqui impede replays do mesmo desafio.
            byte[] nonce = activeNonces.remove(fingerprint);
            if (nonce == null) {
                sendSignedResponse(out, "ERROR:NO_ACTIVE_CHALLENGE");
                return;
            }

            // Verifica password (PBKDF2)
            byte[] checkHash = pbkdf2(password.toCharArray(), rec.pwdSalt, 200_000, 32);
            if (!MessageDigest.isEqual(checkHash, rec.pwdHash)) {
                sendSignedResponse(out, "ERROR:BAD_PASSWORD");
                return;
            }

            // Mensagem do challenge: "AUTH|fingerprint|nonceB64"
            String nonceB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
            String msg = "AUTH|" + fingerprint + "|" + nonceB64;

            // Verifica que o cliente assinou corretamente o challenge com a sua private key
            if (!verifyEcSignature(msg.getBytes(StandardCharsets.UTF_8), signature, pk)) {
                sendSignedResponse(out, "ERROR:BAD_SIGNATURE");
                return;
            }

            // Cria jti para identificar token emitido
            String jti = UUID.randomUUID().toString();

            // Gera JWT assinado pelo OAS:
            // - iss = "OAS"
            // - sub = fingerprint do user
            // - ttl = TOKEN_TTL_SECONDS
            // - scope fixo com permissões para OBSS
            String token = JwtUtils.generateToken(
                signingKeyPair.getPrivate(),
                "OAS",
                fingerprint,
                TOKEN_TTL_SECONDS,
                "obss:get obss:search obss:share",
                jti
            );

            // Guarda jti numa tabela com “expiração” local
            // (Nota: no código atual, este mapa não é usado para validar tokens,
            // apenas para limpar registos de tokens emitidos.)
            issuedTokens.put(jti, System.currentTimeMillis() + (TOKEN_TTL_SECONDS * 1000));

            // Resposta: "OK" + token + assinatura do OAS sobre (OK+token)
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

    // =========================
    // UTIL: valida timestamp + assinatura do pedido
    // =========================
    private static void validateRequestSignature(byte[] clientPubKeyBytes, byte[] signedData, byte[] signature, long timestamp) throws GeneralSecurityException {
        long now = System.currentTimeMillis();

        // Anti-replay: se timestamp estiver fora da janela aceitável, rejeita
        if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_MS) {
            throw new GeneralSecurityException("Timestamp inválido ou expirado (Replay?)");
        }

        // Reconstrói PublicKey do cliente
        PublicKey clientKey = decodeEcPublicKey(clientPubKeyBytes);

        // Verifica assinatura do cliente sobre os dados do pedido
        if (!verifyEcSignature(signedData, signature, clientKey)) {
            throw new GeneralSecurityException("Assinatura do pedido inválida");
        }
    }

    // Envia uma resposta assinada pelo OAS:
    // formato: UTF(msg) + int(sigLen) + bytes(sig)
    private static void sendSignedResponse(DataOutputStream out, String msg) throws IOException {
        try {
            byte[] data = msg.getBytes(StandardCharsets.UTF_8);

            // Assina a mensagem (ou bytes) com private key do OAS
            byte[] sig = signData(data);

            out.writeUTF(msg);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();
        } catch (GeneralSecurityException e) {
            throw new IOException("Falha a assinar resposta", e);
        }
    }

    // Thread que periodicamente remove tokens expirados do mapa issuedTokens
    private static void cleanupExpiredTokens() {
        while (true) {
            try {
                Thread.sleep(60000); // 1 min
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

    // Assina bytes com a private key do OAS
    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(signingKeyPair.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    // Verifica assinatura ECDSA com a public key fornecida
    private static boolean verifyEcSignature(byte[] data, byte[] signature, PublicKey key) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    // Converte bytes encoded (X509) numa PublicKey EC
    private static PublicKey decodeEcPublicKey(byte[] encoded) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    // PBKDF2 com HmacSHA256 para armazenar passwords de forma segura (salt+iters)
    private static byte[] pbkdf2(char[] password, byte[] salt, int iters, int keyLenBytes) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iters, keyLenBytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    // =========================
    // PERSISTÊNCIA: chave AES do “DB”
    // =========================
    private static SecretKey getOrCreateMetaKey() throws IOException {
        File f = new File(USERS_META_KEY_FILE);

        // Se já existe, lê e reconstrói SecretKey
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new javax.crypto.spec.SecretKeySpec(raw, "AES");
            } catch (Exception e) {
                throw new IOException(e);
            }
        } else {
            // Se não existe, gera uma nova chave AES e guarda em Base64
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

    // Guarda users (map) serializado e cifrado em AES-GCM
    private static void saveUsersMetadata() {
        try {
            // Coloca o map dentro de um blob para serializar
            UsersMetaBlob blob = new UsersMetaBlob(users);

            // Serializa para bytes
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();

            // Gera nonce/IV para GCM
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);

            // Cifra em AES-GCM (confidencialidade + integridade)
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, usersMetaKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain);

            // Escreve ficheiro: nonce || ciphertext+tag
            try (FileOutputStream fos = new FileOutputStream(USERS_META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Lê users do disco (AES-GCM) e carrega para memória
    @SuppressWarnings("unchecked")
    private static void loadUsersMetadata() throws IOException {
        File f = new File(USERS_META_FILE);
        if (!f.exists()) return;

        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES) return;

            // Separa nonce e ciphertext
            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);

            // Decifra e valida tag GCM automaticamente (se falhar => exception)
            Cipher cipher = Cipher.getInstance(META_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, usersMetaKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plain = cipher.doFinal(ct);

            // Desserializa blob
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
                UsersMetaBlob blob = (UsersMetaBlob) ois.readObject();
                if (blob.users != null) users = Collections.synchronizedMap(blob.users);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // =========================
    // PERSISTÊNCIA: par de chaves de assinatura OAS
    // =========================
    private static KeyPair getOrCreateSigningKeyPair() throws IOException, GeneralSecurityException {
        File f = new File(SIGNING_KEY_FILE);

        // Se já existe, lê (pubLen+pubBytes+privLen+privBytes) e reconstrói KeyPair
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
            // Se não existe, gera novo par EC (P-256) e grava em formato “caseiro”
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
