import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

/**
 * CryptoConfig
 * ----------
 * Classe utilitária para carregar configurações criptográficas a partir de um ficheiro
 * (por default "cryptoconfig.txt") e aplicar validações de segurança.
 *
 * Ideia no projeto:
 * - Permitir mudar alguns parâmetros (ex: tamanho de chave, block size) sem recompilar.
 * - Ao mesmo tempo, impedir configurações perigosas/incompatíveis.
 *
 * Formato esperado no ficheiro:
 *   CIPHER=AES/GCM/NoPadding
 *   KEYSIZE=256
 *   HMAC=HmacSHA256
 *   BLOCK_SIZE=4096
 *
 * Linhas vazias e comentários (# ...) são ignorados.
 */
public class CryptoConfig {

    /** Transformação/cipher usado pelo projeto (ex: "AES/GCM/NoPadding") */
    public final String cipher;

    /** Tamanho da chave simétrica em bits (128, 192, 256) */
    public final int keySizeBits;

    /** Algoritmo HMAC permitido (HmacSHA256/384/512) */
    public final String hmacAlg;

    /** Tamanho de bloco (em bytes) usado para operações por blocos (ex: 4096) */
    public final int blockSize;

    /**
     * Construtor privado: força os utilizadores da classe a usarem os métodos load()
     * (para garantir validação e defaults).
     */
    private CryptoConfig(String cipher, int keySizeBits, String hmacAlg, int blockSize) {
        this.cipher = cipher;
        this.keySizeBits = keySizeBits;
        this.hmacAlg = hmacAlg;
        this.blockSize = blockSize;
    }

    /**
     * Carrega configuração do caminho default "cryptoconfig.txt" na diretoria atual.
     */
    public static CryptoConfig load() {
        return load(Paths.get("cryptoconfig.txt"));
    }

    /**
     * Carrega a configuração a partir de um caminho específico.
     *
     * Estratégia:
     * 1) Define defaults seguros.
     * 2) Se o ficheiro existir, tenta ler e substituir valores.
     * 3) Valida as opções para impedir configs inválidas.
     * 4) Devolve um CryptoConfig final.
     */
    public static CryptoConfig load(Path path) {
        // Defaults seguros (caso ficheiro não exista ou tenha erros)
        String cipher = "AES/GCM/NoPadding";
        int keySizeBits = 256;
        String hmacAlg = "HmacSHA256";
        int blockSize = 4096;

        // Converter Path em File para testar existência e abrir InputStream
        File f = (path != null) ? path.toFile() : null;

        if (f != null && f.exists()) {
            // Caso exista, tentar ler linha a linha
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {

                String line;
                while ((line = br.readLine()) != null) {
                    // remove BOM (caso o ficheiro tenha \uFEFF no início)
                    // e também faz trim para limpar espaços
                    line = stripBom(line).trim();

                    // ignora linhas vazias e comentários
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    // procura "chave=valor"
                    int eq = line.indexOf('=');
                    // se não houver '=', ou se '=' for primeiro/último char, ignora
                    if (eq <= 0 || eq == line.length() - 1) continue;

                    // extrair key e value
                    // key -> uppercase para tratar CIPHER, cipher, Cipher igual
                    String k = line.substring(0, eq).trim().toUpperCase(Locale.ROOT);
                    // value -> remove aspas se existirem
                    String v = unquote(line.substring(eq + 1).trim());

                    // aplicar ao campo correspondente
                    switch (k) {
                        case "CIPHER":
                            cipher = v;
                            break;
                        case "KEYSIZE":
                            // parse com fallback em caso de erro
                            keySizeBits = parsePositiveInt(v, keySizeBits);
                            break;
                        case "HMAC":
                            hmacAlg = v;
                            break;
                        case "BLOCK_SIZE":
                            // parse com fallback em caso de erro
                            blockSize = parsePositiveInt(v, blockSize);
                            break;
                        default:
                            // chaves desconhecidas são ignoradas
                            break;
                    }
                }
                System.out.println("Config carregada de: " + f.getName());
            } catch (Exception e) {
                // Se falhar leitura/parse, usar defaults
                System.err.println("Aviso: Falha a ler cryptoconfig.txt (" + e.getMessage() + "). A usar defaults.");
            }
        } else {
            // Se ficheiro não existe, usa defaults
            System.out.println("Aviso: cryptoconfig.txt não encontrado. A usar defaults.");
        }

        // =========================
        // Validações de segurança
        // =========================

        // Projeto exige AES-GCM (não aceita outro modo/algoritmo)
        if (!cipher.equalsIgnoreCase("AES/GCM/NoPadding")) {
            throw new IllegalArgumentException(
                "Erro de Configuração: Este projeto requer CIPHER=AES/GCM/NoPadding. Recebido: " + cipher);
        }

        // Tamanhos AES válidos
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException(
                "Erro de Configuração: KEYSIZE inválido (" + keySizeBits + "). Use 128, 192 ou 256.");
        }

        // Limitar HMAC a versões SHA-2 comuns (evita HmacMD5 etc)
        if (!hmacAlg.equalsIgnoreCase("HmacSHA256") &&
            !hmacAlg.equalsIgnoreCase("HmacSHA384") &&
            !hmacAlg.equalsIgnoreCase("HmacSHA512")) {
            throw new IllegalArgumentException(
                "Erro de Configuração: HMAC inválido (" + hmacAlg + ").");
        }

        // Block size dentro de limites (evita valores minúsculos ou gigantes que causem problemas)
        if (blockSize < 1024 || blockSize > (8 * 1024 * 1024)) {
            throw new IllegalArgumentException(
                "Erro de Configuração: BLOCK_SIZE fora dos limites (1KB - 8MB).");
        }

        // Devolve instância final, já validada
        return new CryptoConfig(cipher, keySizeBits, hmacAlg, blockSize);
    }

    /**
     * Tenta carregar. Se existir config inválida, força defaults seguros.
     * Útil para servidores não morrerem só porque o config foi mal editado.
     */
    public static CryptoConfig getOrDefault() {
        try {
            return load();
        } catch (Exception e) {
            System.err.println("Config inválida (" + e.getMessage() + "). A forçar defaults seguros.");
            return new CryptoConfig("AES/GCM/NoPadding", 256, "HmacSHA256", 4096);
        }
    }

    /**
     * Faz parse de int positivo. Se falhar ou der <= 0, devolve fallback.
     */
    private static int parsePositiveInt(String s, int fallback) {
        try {
            int v = Integer.parseInt(s.trim());
            return (v > 0) ? v : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    /**
     * Remove o BOM (\uFEFF) caso o ficheiro tenha sido guardado com BOM no início.
     * Sem isto, a primeira chave poderia ficar tipo "\uFEFFCIPHER" e falhar parsing.
     */
    private static String stripBom(String s) {
        if (s != null && !s.isEmpty() && s.charAt(0) == '\uFEFF') {
            return s.substring(1);
        }
        return s;
    }

    /**
     * Remove aspas se o valor estiver entre "..." ou '...'.
     * Ex: HMAC="HmacSHA256" -> HmacSHA256
     */
    private static String unquote(String v) {
        if (v.length() >= 2) {
            char a = v.charAt(0), b = v.charAt(v.length() - 1);
            if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                return v.substring(1, v.length() - 1);
            }
        }
        return v;
    }

    /**
     * Representação em string útil para logs/debug.
     */
    @Override
    public String toString() {
        return "CryptoConfig{cipher=" + cipher +
               ", keySize=" + keySizeBits +
               ", hmac=" + hmacAlg +
               ", blockSize=" + blockSize + "}";
    }
}
