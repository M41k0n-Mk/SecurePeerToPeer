package me.m41k0n.infra;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AeadUtils — utilitário simples para cifrar/decifrar mensagens com AES-GCM.
 *
 * Propósito desta classe (visão de produto):
 * - Fornece operações práticas e compactas para proteger as mensagens trocadas no chat P2P:
 *     - derivar uma chave simétrica a partir de duas chaves públicas (apenas para protótipo),
 *     - cifrar um payload com AES-GCM e retornar Base64(IV || ciphertext+tag),
 *     - decifrar o mesmo formato.
 * - Existência: a aplicação precisa de uma camada AEAD para garantir confidencialidade e integridade das mensagens
 *   após o handshake criptográfico. AeadUtils oferece essa funcionalidade de forma direta durante desenvolvimento e testes.
 *
 * Por que essa feature existe:
 * - No fluxo P2P, o handshake deriva uma chave de sessão (AEAD) usada para cifrar/decifrar mensagens do chat.
 * - AeadUtils encapsula as operações AES-GCM usadas para proteger essas mensagens (geração de IV, empacotamento,
 *   AAD opcional, codificação em Base64), facilitando a integração com SecureSession e reduzindo repetição de código.
 * - É intencionalmente simples para agilizar prototipação; em produção a derivação e gestão de chaves deve usar
 *   KDFs e práticas seguras (por exemplo, HKDF sobre o segredo DH do handshake, limpeza de memória, melhor tratamento de erros).
 *
 * Uso e formato:
 * - encryptToBase64(key, plaintext, aad) => Base64( IV(12 bytes) || ciphertext_with_tag )
 * - decryptFromBase64(key, ciphertextB64, aad) => plaintext bytes
 * - aad (Additional Authenticated Data) é opcional e é verificada pelo AES-GCM; usar para associar metadados se necessário.
 *
 * Limitações e recomendações (importante para produto):
 * - A função deriveSharedKey(pubA, pubB) NÃO é um KDF seguro para produção. Ela existe só como utilidade rápida.
 *   Para produção, derive a chave AEAD a partir do segredo DH (X25519) usando HKDF-SHA256 com salt/info.
 * - Trate nonces, replays e lifecycle de chaves na camada de protocolo (o IV aqui é aleatório por mensagem, o ideal é garantir
 *   que a combinação chave/IV nunca seja reutilizada).
 * - Em produção, não encapsule exceções criptográficas em RuntimeException sem tratamento; preferir erros explícitos e logs apropriados.
 * - Limpar (zero) dados sensíveis quando possível.
 */
public final class AeadUtils {

    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    private static final SecureRandom RNG = new SecureRandom();

    private AeadUtils() {}

    public static byte[] deriveSharedKey(byte[] pubA, byte[] pubB) {
        if (pubA == null || pubB == null) throw new IllegalArgumentException("pub keys não podem ser null");
        try {
            String a = Base64.getEncoder().encodeToString(pubA);
            String b = Base64.getEncoder().encodeToString(pubB);
            String left = a.compareTo(b) <= 0 ? a : b;
            String right = a.compareTo(b) <= 0 ? b : a;
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest((left + ":" + right).getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encryptToBase64(byte[] key, byte[] plaintext, byte[] aad) {
        try {
            if (key == null || key.length == 0) throw new IllegalArgumentException("key inválida");
            if (plaintext == null) throw new IllegalArgumentException("plaintext null");
            byte[] iv = new byte[IV_BYTES];
            RNG.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(fitKey(key), "AES");
            GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcm);
            if (aad != null) cipher.updateAAD(aad);
            byte[] ct = cipher.doFinal(plaintext);

            ByteBuffer bb = ByteBuffer.allocate(IV_BYTES + ct.length);
            bb.put(iv);
            bb.put(ct);
            return Base64.getEncoder().encodeToString(bb.array());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptFromBase64(byte[] key, String ciphertextB64, byte[] aad) {
        try {
            if (key == null || key.length == 0) throw new IllegalArgumentException("key inválida");
            if (ciphertextB64 == null) throw new IllegalArgumentException("ciphertext null");
            byte[] all;
            try {
                all = Base64.getDecoder().decode(ciphertextB64);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("ciphertext base64 inválido", ex);
            }
            if (all.length < IV_BYTES + 16) throw new IllegalArgumentException("ciphertext muito curto");
            byte[] iv = Arrays.copyOfRange(all, 0, IV_BYTES);
            byte[] ct = Arrays.copyOfRange(all, IV_BYTES, all.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(fitKey(key), "AES");
            GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcm);
            if (aad != null) cipher.updateAAD(aad);
            return cipher.doFinal(ct);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] fitKey(byte[] key) {
        // Ajusta a chave para 16, 24 ou 32 bytes (usa SHA-256 para derivar 32 bytes se necessário)
        if (key.length == 16 || key.length == 24 || key.length == 32) return key;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(key);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
