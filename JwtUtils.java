import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;

public class JwtUtils {

    public static class JwtPayload {
        public final String issuer;  
        public final String subject; 
        public final long   expires;  
        public final long   issuedAt; 
        public final String jwtId;    
        public final String scope;   
        public final String nonce;   

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
            return "JwtPayload{sub=" + subject +
                   ", scope=" + scope +
                   ", jti=" + jwtId + "}";
        }
    }

    public static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // P-256
        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }

    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope) throws GeneralSecurityException {
        return generateToken(signingKey, issuer, subject, ttlSeconds, scope, null, null);
    }


    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope, String jti) throws GeneralSecurityException {
        return generateToken(signingKey, issuer, subject, ttlSeconds, scope, jti, null);
    }

    public static String generateToken(PrivateKey signingKey, String issuer, String subject, long ttlSeconds, String scope, String jti, String nonce) throws GeneralSecurityException {
        long nowSec = System.currentTimeMillis() / 1000L;
        long expSec = nowSec + ttlSeconds;

        if (jti == null || jti.isBlank()) {
            jti = UUID.randomUUID().toString();
        }

        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

        StringBuilder payload = new StringBuilder();
        payload.append("{");
        payload.append("\"iss\":\"").append(escapeJson(issuer)).append("\",");
        payload.append("\"sub\":\"").append(escapeJson(subject)).append("\",");
        payload.append("\"exp\":").append(expSec).append(",");
        payload.append("\"iat\":").append(nowSec).append(",");
        payload.append("\"jti\":\"").append(escapeJson(jti)).append("\"");

        if (scope != null && !scope.isBlank()) {
            payload.append(",\"scope\":\"").append(escapeJson(scope)).append("\"");
        }
        if (nonce != null && !nonce.isBlank()) {
            payload.append(",\"nonce\":\"").append(escapeJson(nonce)).append("\"");
        }
        payload.append("}");

        String headerB64  = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(payload.toString().getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signature = signEs256(signingInput.getBytes(StandardCharsets.US_ASCII), signingKey);
        String sigB64 = base64UrlEncode(signature);

        return signingInput + "." + sigB64;
    }

    public static JwtPayload verifyAndParse(String token, PublicKey verifyKey, String expectedIssuer) throws GeneralSecurityException {
        if (token == null || token.isBlank()) {
            throw new GeneralSecurityException("Token vazio.");
        }

        token = token.trim();

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new GeneralSecurityException("Formato JWT inválido.");
        }

        String headerB64  = parts[0];
        String payloadB64 = parts[1];
        String sigB64     = parts[2];

        byte[] sigBytes = base64UrlDecode(sigB64);
        String signingInput = headerB64 + "." + payloadB64;
        if (!verifyEs256(signingInput.getBytes(StandardCharsets.US_ASCII), sigBytes, verifyKey)) {
            throw new GeneralSecurityException("Assinatura JWT inválida.");
        }

        byte[] headerBytes = base64UrlDecode(headerB64);
        String headerJson = new String(headerBytes, StandardCharsets.UTF_8);
        String alg = extractJsonString(headerJson, "alg");
        String typ = extractJsonString(headerJson, "typ");

        if (alg == null || !"ES256".equalsIgnoreCase(alg)) {
            throw new GeneralSecurityException("Algoritmo JWT inválido ou ausente: " + alg);
        }

        if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
            throw new GeneralSecurityException("Tipo JWT inesperado: " + typ);
        }

        byte[] payloadBytes = base64UrlDecode(payloadB64);
        String payloadJson = new String(payloadBytes, StandardCharsets.UTF_8);

        String iss   = extractJsonString(payloadJson, "iss");
        String sub   = extractJsonString(payloadJson, "sub");
        long   exp   = extractJsonLong(payloadJson, "exp");
        long   iat   = extractJsonLong(payloadJson, "iat");
        String jti   = extractJsonString(payloadJson, "jti");
        String scope = extractJsonString(payloadJson, "scope");
        String nonce = extractJsonString(payloadJson, "nonce");

        if (iss == null || sub == null || exp == 0L) {
            throw new GeneralSecurityException("Payload JWT incompleto.");
        }

        if (expectedIssuer != null && !expectedIssuer.equals(iss)) {
            throw new GeneralSecurityException("Issuer inválido: " + iss);
        }

        long nowSec = System.currentTimeMillis() / 1000L;
        if (exp < nowSec) {
            throw new GeneralSecurityException("Token expirado.");
        }

        return new JwtPayload(iss, sub, exp, iat, jti, scope, nonce);
    }

    public static boolean hasScope(JwtPayload payload, String requiredScope) {
        if (payload == null || payload.scope == null || requiredScope == null) {
            return false;
        }
        String req = requiredScope.trim();
        if (req.isEmpty()) return false;

        String[] scopes = payload.scope.split("\\s+");
        for (String s : scopes) {
            if (s.equals(req)) {
                return true;
            }
        }
        return false;
    }

    public static boolean hasAnyScope(JwtPayload payload, String... requiredScopes) {
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
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    private static boolean verifyEs256(byte[] data, byte[] signature, PublicKey key)
            throws GeneralSecurityException {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] base64UrlDecode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String extractJsonString(String json, String key) {
        if (json == null) return null;
        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;

        idx += pattern.length();
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;

        if (idx >= json.length() || json.charAt(idx) != '"') return null; 

        idx++; 
        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        while (idx < json.length()) {
            char c = json.charAt(idx++);
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else {
                if (c == '\\') escaped = true;
                else if (c == '"') break; 
                else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static long extractJsonLong(String json, String key) {
        if (json == null) return 0L;
        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return 0L;

        idx += pattern.length();
        while (idx < json.length()
                && !Character.isDigit(json.charAt(idx))
                && json.charAt(idx) != '-') {
            idx++;
        }

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
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(pk.getEncoded());
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
