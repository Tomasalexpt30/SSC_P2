import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;

public class JwtUtils {

    // Estrutura simples para devolver os campos do payload já “parsed”
    public static class JwtPayload {
        public final String issuer;   // "iss" - quem emitiu o token (ex: "OAS")
        public final String subject;  // "sub" - sujeito do token (no projeto: fingerprint do user)
        public final long   expires;  // "exp" - expiry time (epoch seconds)
        public final long   issuedAt; // "iat" - issued at (epoch seconds)
        public final String jwtId;    // "jti" - id único do token
        public final String scope;    // "scope" - permissões (ex: "obss:get obss:search obss:share")
        public final String nonce;    // "nonce" - opcional (não é sempre usado)

        public JwtPayload(String issuer, String subject, long expires,
                          long issuedAt, String jwtId, String scope, String nonce) {
            this.issuer   = issuer;
            this.subject  = subject;
            this.expires  = expires;
            this.issuedAt = issuedAt;
            this.jwtId    = jwtId;
            this.scope    = scope;
            this.nonce    = nonce;
        }

        @Override
        public String toString() {
            // Só para debug/log: mostra sub, scope e jti
            return "JwtPayload{sub=" + subject +
                   ", scope=" + scope +
                   ", jti=" + jwtId + "}";
        }
    }

    public static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        // Gera par de chaves EC (Elliptic Curve) para assinaturas ECDSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        // Usa a curva secp256r1 (P-256) => compatível com ES256
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256
        kpg.initialize(ecSpec);

        // Devolve (PublicKey, PrivateKey)
        return kpg.generateKeyPair();
    }

    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope) throws GeneralSecurityException {
        // Overload simples: não fornece jti nem nonce
        return generateToken(signingKey, issuer, subject, ttlSeconds, scope, null, null);
    }

    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope, String jti) throws GeneralSecurityException {
        // Overload: permite fornecer jti, mas não nonce
        return generateToken(signingKey, issuer, subject, ttlSeconds, scope, jti, null);
    }

    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope, String jti, String nonce) throws GeneralSecurityException {
        // "now" e "exp" em epoch seconds (padrão JWT)
        long nowSec = System.currentTimeMillis() / 1000L;
        long expSec = nowSec + ttlSeconds;

        // Se não derem jti, cria um UUID para identificar unicamente o token
        if (jti == null || jti.isBlank()) {
            jti = UUID.randomUUID().toString();
        }

        // Header JWT (JSON). alg=ES256 significa ECDSA + SHA-256
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

        // Construção manual do payload JSON com os campos essenciais do projeto
        StringBuilder payload = new StringBuilder();
        payload.append("{");
        payload.append("\"iss\":\"").append(escapeJson(issuer)).append("\",");
        payload.append("\"sub\":\"").append(escapeJson(subject)).append("\",");
        payload.append("\"exp\":").append(expSec).append(",");
        payload.append("\"iat\":").append(nowSec).append(",");
        payload.append("\"jti\":\"").append(escapeJson(jti)).append("\"");

        // scope é opcional, mas é o que suporta autorização no projeto (obss:get, obss:search, obss:share)
        if (scope != null && !scope.isBlank()) {
            payload.append(",\"scope\":\"").append(escapeJson(scope)).append("\"");
        }

        // nonce opcional (pode existir, mas nem sempre é usado)
        if (nonce != null && !nonce.isBlank()) {
            payload.append(",\"nonce\":\"").append(escapeJson(nonce)).append("\"");
        }
        payload.append("}");

        // JWT usa Base64URL sem padding (=)
        String headerB64  = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(payload.toString().getBytes(StandardCharsets.UTF_8));

        // O que é efetivamente assinado no JWT
        String signingInput = headerB64 + "." + payloadB64;

        // Assinatura ES256 = SHA256withECDSA no Java
        byte[] signature = signEs256(signingInput.getBytes(StandardCharsets.US_ASCII), signingKey);
        String sigB64 = base64UrlEncode(signature);

        // Token final: header.payload.signature
        return signingInput + "." + sigB64;
    }

    public static JwtPayload verifyAndParse(String token, PublicKey verifyKey, String expectedIssuer) throws GeneralSecurityException {
        // Verificação básica de null/vazio
        if (token == null || token.isBlank()) {
            throw new GeneralSecurityException("Token vazio.");
        }

        token = token.trim();

        // JWT tem 3 partes separadas por "."
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new GeneralSecurityException("Formato JWT inválido.");
        }

        String headerB64  = parts[0];
        String payloadB64 = parts[1];
        String sigB64     = parts[2];

        // 1) Verificar assinatura primeiro (não confiar em conteúdo antes de validar)
        byte[] sigBytes = base64UrlDecode(sigB64);
        String signingInput = headerB64 + "." + payloadB64;
        if (!verifyEs256(signingInput.getBytes(StandardCharsets.US_ASCII), sigBytes, verifyKey)) {
            throw new GeneralSecurityException("Assinatura JWT inválida.");
        }

        // 2) Validar header: alg e typ
        byte[] headerBytes = base64UrlDecode(headerB64);
        String headerJson = new String(headerBytes, StandardCharsets.UTF_8);
        String alg = extractJsonString(headerJson, "alg");
        String typ = extractJsonString(headerJson, "typ");

        // Só aceitamos ES256
        if (alg == null || !"ES256".equalsIgnoreCase(alg)) {
            throw new GeneralSecurityException("Algoritmo JWT inválido ou ausente: " + alg);
        }

        // typ pode ser null, mas se existir tem de ser JWT
        if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
            throw new GeneralSecurityException("Tipo JWT inesperado: " + typ);
        }

        // 3) Ler o payload e extrair os campos
        byte[] payloadBytes = base64UrlDecode(payloadB64);
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);

        String iss   = extractJsonString(payloadJson, "iss");
        String sub   = extractJsonString(payloadJson, "sub");
        long   exp   = extractJsonLong(payloadJson, "exp");
        long   iat   = extractJsonLong(payloadJson, "iat");
        String jti   = extractJsonString(payloadJson, "jti");
        String scope = extractJsonString(payloadJson, "scope");
        String nonce = extractJsonString(payloadJson, "nonce");

        // Campos mínimos esperados
        if (iss == null || sub == null || exp == 0L) {
            throw new GeneralSecurityException("Payload JWT incompleto.");
        }

        // Se esperarmos um issuer específico (ex: "OAS"), validar
        if (expectedIssuer != null && !expectedIssuer.equals(iss)) {
            throw new GeneralSecurityException("Issuer inválido: " + iss);
        }

        // Validar expiração
        long nowSec = System.currentTimeMillis() / 1000L;
        if (exp < nowSec) {
            throw new GeneralSecurityException("Token expirado.");
        }

        // Se tudo OK, devolve um objeto com os campos
        return new JwtPayload(iss, sub, exp, iat, jti, scope, nonce);
    }

    public static boolean hasScope(JwtPayload payload, String requiredScope) {
        // Validações básicas
        if (payload == null || payload.scope == null || requiredScope == null) {
            return false;
        }

        String req = requiredScope.trim();
        if (req.isEmpty()) return false;

        // Scopes separados por espaço (ex: "obss:get obss:search obss:share")
        String[] scopes = payload.scope.split("\\s+");
        for (String s : scopes) {
            if (s.equals(req)) { // comparação exata
                return true;
            }
        }
        return false;
    }

    public static boolean hasAnyScope(JwtPayload payload, String... requiredScopes) {
        // Verifica se tem pelo menos 1 dos scopes fornecidos
        if (payload == null || payload.scope == null || requiredScopes == null) {
            return false;
        }
        for (String req : requiredScopes) {
            if (req != null && !req.isBlank() && hasScope(payload, req)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] signEs256(byte[] data, PrivateKey key) throws GeneralSecurityException {
        // Assinatura ECDSA com SHA-256 (ES256)
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    private static boolean verifyEs256(byte[] data, byte[] signature, PublicKey key)
            throws GeneralSecurityException {
        // Verificação da assinatura ECDSA com SHA-256
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    private static String base64UrlEncode(byte[] data) {
        // Base64 URL-safe, sem padding ("=") => formato JWT
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] base64UrlDecode(String s) {
        // Decoder URL-safe correspondente
        return Base64.getUrlDecoder().decode(s);
    }

    private static String escapeJson(String s) {
        // Escapa caracteres básicos para o JSON não partir (\" e \\)
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String extractJsonString(String json, String key) {
        // Parser MUITO simples: procura padrão "key": "value"
        // Serve porque o payload gerado é simples e plano (sem nesting)
        if (json == null) return null;

        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;

        idx += pattern.length();

        // saltar whitespace
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;

        // esperamos começar com aspas
        if (idx >= json.length() || json.charAt(idx) != '"') return null;

        idx++; // entra na string
        StringBuilder sb = new StringBuilder();
        boolean escaped = false;

        while (idx < json.length()) {
            char c = json.charAt(idx++);
            if (escaped) {
                // char escapado
                sb.append(c);
                escaped = false;
            } else {
                if (c == '\\') escaped = true; // próxima char é escapada
                else if (c == '"') break;      // fim da string
                else sb.append(c);             // char normal
            }
        }
        return sb.toString();
    }

    private static long extractJsonLong(String json, String key) {
        // Parser simples para números (exp, iat, etc.)
        if (json == null) return 0L;

        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return 0L;

        idx += pattern.length();

        // avançar até encontrar dígito ou '-'
        while (idx < json.length()
                && !Character.isDigit(json.charAt(idx))
                && json.charAt(idx) != '-') {
            idx++;
        }

        // ler número
        StringBuilder sb = new StringBuilder();
        while (idx < json.length()) {
            char c = json.charAt(idx++);
            if (Character.isDigit(c) || c == '-') sb.append(c);
            else break;
        }

        try {
            return Long.parseLong(sb.toString());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    public static String publicKeyFingerprint(PublicKey pk) throws GeneralSecurityException {
        // Fingerprint = SHA-256 da public key codificada (pk.getEncoded()) em hex.
        // No projeto isto é usado como "identificador do utilizador" (subject/sub).
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(pk.getEncoded());

        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
