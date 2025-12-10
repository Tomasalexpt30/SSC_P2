import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

public class CryptoConfig {
    public final String cipher;
    public final int keySizeBits;
    public final String hmacAlg;
    public final int blockSize;

    private CryptoConfig(String cipher, int keySizeBits, String hmacAlg, int blockSize) {
        this.cipher = cipher;
        this.keySizeBits = keySizeBits;
        this.hmacAlg = hmacAlg;
        this.blockSize = blockSize;
    }

    public static CryptoConfig load() {
        return load(Paths.get("cryptoconfig.txt"));
    }

    public static CryptoConfig load(Path path) {
        String cipher = "AES/GCM/NoPadding";
        int keySizeBits = 256;
        String hmacAlg = "HmacSHA256";
        int blockSize = 4096;

        File f = (path != null) ? path.toFile() : null;
        if (f != null && f.exists()) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {

                String line;
                while ((line = br.readLine()) != null) {
                    line = stripBom(line).trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    int eq = line.indexOf('=');
                    if (eq <= 0 || eq == line.length() - 1) continue;

                    String k = line.substring(0, eq).trim().toUpperCase(Locale.ROOT);
                    String v = unquote(line.substring(eq + 1).trim());

                    switch (k) {
                        case "CIPHER":
                            cipher = v;
                            break;
                        case "KEYSIZE":
                            keySizeBits = parsePositiveInt(v, keySizeBits);
                            break;
                        case "HMAC":
                            hmacAlg = v;
                            break;
                        case "BLOCK_SIZE":
                            blockSize = parsePositiveInt(v, blockSize);
                            break;
                        default:
                            break;
                    }
                }
                System.out.println("Config carregada de: " + f.getName());
            } catch (Exception e) {
                System.err.println("Aviso: Falha a ler cryptoconfig.txt (" + e.getMessage() + "). A usar defaults.");
            }
        } else {
            System.out.println("Aviso: cryptoconfig.txt não encontrado. A usar defaults.");
        }

        if (!cipher.equalsIgnoreCase("AES/GCM/NoPadding")) {
            throw new IllegalArgumentException(
                "Erro de Configuração: Este projeto requer CIPHER=AES/GCM/NoPadding. Recebido: " + cipher);
        }
        
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException("Erro de Configuração: KEYSIZE inválido (" + keySizeBits + "). Use 128, 192 ou 256.");
        }
        
        if (!hmacAlg.equalsIgnoreCase("HmacSHA256") &&
            !hmacAlg.equalsIgnoreCase("HmacSHA384") &&
            !hmacAlg.equalsIgnoreCase("HmacSHA512")) {
            throw new IllegalArgumentException("Erro de Configuração: HMAC inválido (" + hmacAlg + ").");
        }
        
        if (blockSize < 1024 || blockSize > (8 * 1024 * 1024)) {
            throw new IllegalArgumentException("Erro de Configuração: BLOCK_SIZE fora dos limites (1KB - 8MB).");
        }

        return new CryptoConfig(cipher, keySizeBits, hmacAlg, blockSize);
    }

    public static CryptoConfig getOrDefault() {
        try { 
            return load(); 
        } catch (Exception e) {
            System.err.println("Config inválida (" + e.getMessage() + "). A forçar defaults seguros.");
            return new CryptoConfig("AES/GCM/NoPadding", 256, "HmacSHA256", 4096);
        }
    }

    private static int parsePositiveInt(String s, int fallback) {
        try {
            int v = Integer.parseInt(s.trim());
            return (v > 0) ? v : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    private static String stripBom(String s) {
        if (s != null && !s.isEmpty() && s.charAt(0) == '\uFEFF') {
            return s.substring(1);
        }
        return s;
    }

    private static String unquote(String v) {
        if (v.length() >= 2) {
            char a = v.charAt(0), b = v.charAt(v.length() - 1);
            if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                return v.substring(1, v.length() - 1);
            }
        }
        return v;
    }

    @Override
    public String toString() {
        return "CryptoConfig{cipher=" + cipher +
               ", keySize=" + keySizeBits +
               ", hmac=" + hmacAlg +
               ", blockSize=" + blockSize + "}";
    }
}