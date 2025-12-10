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
    private static final String HOST = "localhost";
    private static final int PORT_OAS  = 6000;
    private static final int PORT_OAMS = 7000;
    private static final int PORT_OBSS = 5000;
    
    private static final String SIGN_ALGO = "SHA256withECDSA";
    private static final String FILE_CIPHER = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_LEN = 128;

    private static final String USER_KEY_FILE = System.getProperty("p2.userKeyFile", "user.keys");
    private static final String TRUSTSTORE_FILE = "clienttruststore.jks";


    private static PublicKey oasPublicKey;
    private static PublicKey oamsPublicKey;

    private static KeyPair userKeyPair;    
    private static String userFingerprint; 
    private static String jwtToken = null; 

    private static final Scanner scanner = new Scanner(System.in);
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) {
        try {
            initTLS();
            loadServerKeys(); 
            loadIdentity();   
            
            mainMenu();
        } catch (Exception e) {
            System.err.println("Erro Fatal no Cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initTLS() {
        System.setProperty("javax.net.ssl.trustStore", TRUSTSTORE_FILE);
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    private static void loadServerKeys() {
        try {
            oasPublicKey = loadPublicKeyFromFile("oas_signing_keypair.bin");
            oamsPublicKey = loadPublicKeyFromFile("oams_signing_keypair.bin");
            System.out.println("[Init] Chaves públicas dos servidores carregadas.");
        } catch (Exception e) {
            System.out.println("[WARN] Não foi possível carregar chaves dos servidores (Validação de assinatura falhará).");
        }
    }

    private static void mainMenu() throws Exception {
        while (true) {
            System.out.println("\n=========== PROJECT 2 SECURE CLIENT ===========");
        if (userFingerprint != null) {
            System.out.println("User FP: " + userFingerprint);
            System.out.println("User: " + userFingerprint.substring(0, 8) + "...");
        } else {
            System.out.println("User: Não registado/carregado");
        }
        System.out.println("Auth: " + (jwtToken != null ? "SIM" : "NÃO"));

            
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
        userKeyPair = JwtUtils.generateEcKeyPair();
        userFingerprint = JwtUtils.publicKeyFingerprint(userKeyPair.getPublic());
        saveIdentity(); 

        System.out.println("Nova identidade criada.");
        System.out.println("Fingerprint (User FP): " + userFingerprint);


        byte[] pubBytes = userKeyPair.getPublic().getEncoded();
        System.out.print("Escolha uma Password: ");
        String pwd = scanner.nextLine().trim();
        Map<String, String> attrs = new HashMap<>();
        
        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CREATE_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(pwd);
            dos.writeInt(attrs.size()); 
            dos.writeLong(timestamp);

            byte[] signature = signData(baos.toByteArray());

            out.writeUTF("CREATE_REG");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeInt(attrs.size());
            out.writeLong(timestamp);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();

            readSignedResponse(in, oasPublicKey);
            System.out.println("Identidade criada e salva em '" + USER_KEY_FILE + "'.");
        }
    }

    private static void authenticate() throws Exception {
        if (userKeyPair == null) {
            System.out.println("Erro: Nenhuma identidade carregada.");
            return;
        }
        System.out.print("Password: ");
        String pwd = scanner.nextLine().trim();
        byte[] pubBytes = userKeyPair.getPublic().getEncoded();

        byte[] nonce;
        try (SSLSocket socket = connectTLS(PORT_OAS);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream())) {
            
            out.writeUTF("AUTH_START");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.flush();

            String status = in.readUTF();

            if (!"OK".equals(status)) {
                int sigLen = in.readInt();
                byte[] sig = new byte[sigLen];
                in.readFully(sig);

                if (!verifySignature(status.getBytes(StandardCharsets.UTF_8), sig, oasPublicKey)) {
                    System.out.println("ERRO FATAL: Resposta do OAS com assinatura inválida: " + status);
                } else {
                    System.out.println("Servidor OAS: " + status);
                }
                return;
            }

            int nonceLen = in.readInt();
            nonce = new byte[nonceLen];
            in.readFully(nonce);

            int sigLen = in.readInt();
            byte[] sig = new byte[sigLen];
            in.readFully(sig);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("OK");
            dos.writeInt(nonceLen);
            dos.write(nonce);
            
            if (!verifySignature(baos.toByteArray(), sig, oasPublicKey)) {
                System.out.println("ERRO FATAL: Assinatura do OAS inválida! Possível ataque.");
                return;
            }
        }

        try (SSLSocket socket = connectTLS(PORT_OAS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            String nonceB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
            String challengeMsg = "AUTH|" + userFingerprint + "|" + nonceB64;
            byte[] signature = signData(challengeMsg.getBytes(StandardCharsets.UTF_8));

            out.writeUTF("AUTH_FINISH");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush();

            String status = in.readUTF();
            if ("OK".equals(status)) {
                String token = in.readUTF();
                int sLen = in.readInt();
                byte[] sig = new byte[sLen];
                in.readFully(sig);

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeUTF("OK");
                dos.writeUTF(token);
                
                if (verifySignature(baos.toByteArray(), sig, oasPublicKey)) {
                    jwtToken = token;
                    System.out.println("Autenticado com sucesso.");
                } else {
                    System.out.println("ERRO: Token recebido com assinatura inválida.");
                }
            } else {
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
        if (jwtToken == null) { System.out.println("Login necessário."); return; }
        
        System.out.print("Caminho do ficheiro: ");
        String path = scanner.nextLine().trim();
        File f = new File(path);
        if (!f.exists()) { System.out.println("Ficheiro não encontrado."); return; }

        String docId = UUID.randomUUID().toString();
        System.out.print("Keywords (separadas por vírgula): ");
        String kwInput = scanner.nextLine().trim();
        List<String> kws = new ArrayList<>();

        if(!kwInput.isEmpty()) {
            for(String k : kwInput.split(",")) kws.add(hashString(k.trim().toLowerCase()));
        }

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey fileKey = kg.generateKey();

        try (SSLSocket socket = connectTLS(PORT_OBSS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream());
             FileInputStream fis = new FileInputStream(f)) {

            byte[] buf = new byte[1024 * 1024]; 
            int read;
            boolean first = true;
            
            System.out.println("A encriptar e enviar docID: " + docId);

            while ((read = fis.read(buf)) != -1) {
                byte[] chunk = Arrays.copyOf(buf, read);

                String plaintextHash = hashBytes(chunk);

                byte[] iv = new byte[GCM_IV_LEN];
                RNG.nextBytes(iv);
                EncryptionResult encResult = encryptAesGcm(chunk, fileKey, iv);
                
                out.writeUTF("STORE_BLOCK");
                out.writeUTF(jwtToken); 
                out.writeUTF(UUID.randomUUID().toString());
                out.writeUTF(plaintextHash); 

                byte[] ivAndCipher = new byte[iv.length + encResult.ciphertext.length];
                System.arraycopy(iv, 0, ivAndCipher, 0, iv.length);
                System.arraycopy(encResult.ciphertext, 0, ivAndCipher, iv.length, encResult.ciphertext.length);
                
                out.writeInt(ivAndCipher.length);
                out.write(ivAndCipher);
   
                out.writeInt(encResult.authTag.length);
                out.write(encResult.authTag);

                if (first) {
                    out.writeInt(kws.size() + 1);
                    out.writeUTF(docId);
                    for (String k : kws) out.writeUTF(k);
                    first = false;
                } else {
                    out.writeInt(1);
                    out.writeUTF(docId);
                }
                out.flush();
                
                String resp = in.readUTF();
                if (!resp.startsWith("OK")) throw new IOException("OBSS Error: " + resp);
            }
        }

        byte[] wrappedKey = fileKey.getEncoded(); 
        registerShareInOams(docId, userFingerprint, "GET SEARCH SHARE", wrappedKey);
        
        System.out.println("Ficheiro guardado com sucesso! DocID: " + docId);
    }

    private static void downloadFile() throws Exception {
        if (jwtToken == null) { System.out.println("Login necessário."); return; }
        System.out.print("DocID: ");
        String docId = scanner.nextLine().trim();

        byte[] keyBlob = checkAccessAndGetKey(docId, "GET");
        if (keyBlob == null || keyBlob.length == 0) {
            System.out.println("Acesso negado ou chave não encontrada.");
            return;
        }

        SecretKey fileKey = new SecretKeySpec(keyBlob, "AES");

        try (SSLSocket socket = connectTLS(PORT_OBSS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            out.writeUTF("GET_DOC_BLOCKS");
            out.writeUTF(jwtToken);
            out.writeUTF(docId);
            out.flush();

            int count = in.readInt();
            if (count <= 0) { System.out.println("Ficheiro vazio ou inexistente."); return; }

            File outFile = new File("downloaded_" + docId + ".bin");
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                for (int i = 0; i < count; i++) {
                    String blockId = in.readUTF();

                    out.writeUTF("GET_BLOCK");
                    out.writeUTF(jwtToken);
                    out.writeUTF(blockId);
                    out.flush();

                    int cipherLen = in.readInt();

                    if (cipherLen <= 0) {
                        System.out.println("Falha ao obter bloco " + blockId +
                                " (possível falta de permissão ou token expirado).");
                        return;
                    }

                    byte[] ivAndCipher = new byte[cipherLen];
                    in.readFully(ivAndCipher);

                    int tagLen = in.readInt();
                    if (tagLen <= 0) {
                        System.out.println("Falha ao obter tag do bloco " + blockId +
                                " (dados inválidos).");
                        return;
                    }

                    byte[] authTag = new byte[tagLen];
                    in.readFully(authTag);

                    if (cipherLen < GCM_IV_LEN) {
                        throw new IOException("Dados corrompidos (bloco demasiado pequeno).");
                    }
                    byte[] iv = Arrays.copyOfRange(ivAndCipher, 0, GCM_IV_LEN);
                    byte[] ciphertext = Arrays.copyOfRange(ivAndCipher, GCM_IV_LEN, cipherLen);

                    byte[] plaintext = decryptAesGcm(ciphertext, authTag, fileKey, iv);
                    fos.write(plaintext);
                }
            }
            System.out.println("Ficheiro decifrado e salvo: " + outFile.getName());
        }
    }

    private static void searchFiles() throws Exception {
        if (jwtToken == null) {
            System.out.println("Login necessário.");
            return;
        }

        byte[] res = checkAccessAndGetKey("ANY", "SEARCH");
        if (res == null) {
            System.out.println("Sem permissão para pesquisar (scope obss:search em falta).");
            return;
        }

        System.out.print("Keyword: ");
        String kw = scanner.nextLine().trim().toLowerCase();
        String hashedKw = hashString(kw);

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
        try (SSLSocket socket = connectTLS(PORT_OAMS);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();

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
            byte[] sig = signData(baos.toByteArray());

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

            readSignedResponse(in, oamsPublicKey);
        }
    }

    private static byte[] checkAccessAndGetKey(String docId, String perm) {
        try (SSLSocket socket = connectTLS(PORT_OAMS);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("CHECK_ACCESS");
            dos.writeUTF(jwtToken);
            dos.writeUTF(docId);
            dos.writeUTF(perm);
            dos.writeLong(timestamp);
            byte[] sig = signData(baos.toByteArray());

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

            String status = in.readUTF();

            if ("OK".equals(status)) {
                int blobLen = in.readInt();
                byte[] keyBlob = new byte[blobLen];
                if (blobLen > 0) in.readFully(keyBlob);

                int sLen = in.readInt();
                byte[] serverSig = new byte[sLen];
                in.readFully(serverSig);

                ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
                DataOutputStream respDos = new DataOutputStream(respBaos);
                respDos.writeUTF(status);
                respDos.writeInt(blobLen);
                if (blobLen > 0) respDos.write(keyBlob);

                if (!verifySignature(respBaos.toByteArray(), serverSig, oamsPublicKey)) {
                    System.out.println("ALERTA: Resposta OAMS com assinatura inválida.");
                    return null;
                }

                return keyBlob; 

            } else {
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

        byte[] keyBlob = checkAccessAndGetKey(d, "GET");
        if (keyBlob == null || keyBlob.length == 0) {
            System.out.println("Não foi possível obter a chave do documento (sem acesso ou doc inexistente).");
            return;
        }
        registerShareInOams(d, g, p, keyBlob);
        System.out.println("Partilha criada com sucesso para " + g);
    }

    private static void deleteShare() throws Exception {
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

        try (SSLSocket socket = connectTLS(PORT_OAMS);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream())) {

            long timestamp = System.currentTimeMillis();
            byte[] pubBytes = userKeyPair.getPublic().getEncoded();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_SHARE");
            dos.writeUTF(jwtToken);
            dos.writeUTF(d);
            dos.writeUTF(g);
            dos.writeLong(timestamp);
            byte[] sig = signData(baos.toByteArray());

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

            readSignedResponse(in, oamsPublicKey);
        }
    }

    
    private static void manageAccount() throws Exception {
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
                    return; 
                default:
                    System.out.println("Opção inválida.");
            }
        }
    }

    private static void changePassword() throws Exception {
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

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("MODIFY_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(currentPwd);
            dos.writeUTF(newPwd);
            dos.writeInt(0); 
            dos.writeLong(timestamp);
            byte[] sig = signData(baos.toByteArray());

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

            readSignedResponse(in, oasPublicKey);
        }
    }

    private static void deleteAccount() throws Exception {
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

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeUTF("DELETE_REG");
            dos.writeInt(pubBytes.length);
            dos.write(pubBytes);
            dos.writeUTF(pwd);
            dos.writeLong(timestamp);
            byte[] sig = signData(baos.toByteArray());

            out.writeUTF("DELETE_REG");
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.writeUTF(pwd);
            out.writeLong(timestamp);
            out.writeInt(sig.length);
            out.write(sig);
            out.flush();

            readSignedResponse(in, oasPublicKey);
        }

        userKeyPair = null;
        userFingerprint = null;
        jwtToken = null;
        new File(USER_KEY_FILE).delete();
        System.out.println("Identidade local removida. Vai precisar de criar nova identidade.");
    }


    private static byte[] signData(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIGN_ALGO);
        sig.initSign(userKeyPair.getPrivate());
        sig.update(data);
        return sig.sign();
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey key) {
        try {
            Signature sig = Signature.getInstance(SIGN_ALGO);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) { return false; }
    }

    private static class EncryptionResult {
        byte[] ciphertext;
        byte[] authTag;
        EncryptionResult(byte[] c, byte[] t) { ciphertext = c; authTag = t; }
    }

    private static EncryptionResult encryptAesGcm(byte[] plaintext, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(FILE_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));
        byte[] output = cipher.doFinal(plaintext);

        int tagBytes = GCM_TAG_LEN / 8;
        byte[] cText = Arrays.copyOfRange(output, 0, output.length - tagBytes);
        byte[] tag = Arrays.copyOfRange(output, output.length - tagBytes, output.length);
        return new EncryptionResult(cText, tag);
    }

    private static byte[] decryptAesGcm(byte[] ciphertext, byte[] tag, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(FILE_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LEN, iv));

        byte[] input = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
        System.arraycopy(tag, 0, input, ciphertext.length, tag.length);
        
        return cipher.doFinal(input);
    }

    private static void saveIdentity() throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USER_KEY_FILE))) {
            oos.writeObject(userKeyPair);
        }
        System.out.println("Identidade guardada em disco.");
    }

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

    private static PublicKey loadPublicKeyFromFile(String path) throws Exception {
        try (DataInputStream in = new DataInputStream(new FileInputStream(path))) {
            int len = in.readInt();
            byte[] b = new byte[len];
            in.readFully(b);
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(b));
        }
    }

    private static String hashString(String input) {
        return hashBytes(input.getBytes(StandardCharsets.UTF_8));
    }
    
    private static String hashBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input);
            StringBuilder sb = new StringBuilder();
            for(byte b: d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch(Exception e) { return ""; }
    }

    private static void readSignedResponse(DataInputStream in, PublicKey serverKey) throws IOException {
        String msg = in.readUTF();
        int len = in.readInt();
        byte[] sig = new byte[len];
        in.readFully(sig);
        
        if (!verifySignature(msg.getBytes(StandardCharsets.UTF_8), sig, serverKey)) {
            throw new IOException("Assinatura do servidor INVALIDA na resposta: " + msg);
        }
        System.out.println("Servidor: " + msg + " (Assinatura Validada)");
    }
    
    private static SSLSocket connectTLS(int port) throws IOException {
        SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        return (SSLSocket) sslFactory.createSocket(HOST, port);
    }
}