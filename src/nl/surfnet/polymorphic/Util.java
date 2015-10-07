package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Static class that provides different helper functions.
 */
public class Util {
    private static SecureRandom prng;

    static {
        try {
            prng = SecureRandom.getInstance("SHA1PRNG");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Key derivation function.
     *
     * @param k The key for the KDF
     * @param data The data for the KDF
     * @return The derived key
     */
    public static BigInteger KDF(byte[] k, byte[] data) {
        try {
            Mac hMac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(k, "HmacSHA256");
            hMac.init(key);
            byte[] bytes = hMac.doFinal(data);
            return new BigInteger(1, bytes);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Hashes the given data.
     *
     * @param data The data to hash
     * @return byte-array containing the hashed data
     */
    public static byte[] Hash(byte[] data) {
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(data, 0, data.length);
        byte[] out = new byte[sha256.getDigestSize()];
        sha256.doFinal(out, 0);
        return out;
    }

    /**
     * Embeds data into the elliptic curve.
     *
     * @param bytes The data to embed
     * @return The {@link ECPoint} representing the data
     */
    public static ECPoint embed(byte[] bytes) {
        byte counter = 0;
        ECFieldElement x = null,  y = null;
        while(y == null) {
            x = SystemParams.getCurve().fromBigInteger(new BigInteger(bytes));
            y = x.square().multiply(x)
                    .add(x.multiply(SystemParams.getCurve().getA()))
                    .add(SystemParams.getCurve().getB())
                    .sqrt();
            if(counter == 0) {
                bytes = Arrays.copyOf(bytes, bytes.length + 1);
            }
            counter++;
            bytes[bytes.length - 1] = counter;
        }
        return SystemParams.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
    }

    /**
     * Generate secure random bytes.
     *
     * @param num The number of random bytes to generate
     * @return byte array of length num containing secure random bytes
     */
    public static byte[] randomBytes(int num) {
        byte[] bytes = new byte[num];
        prng.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generate a secure random {@link BigInteger}
     * @return A secure random {@link BigInteger}
     */
    public static BigInteger random() {
        return new BigInteger(1, randomBytes(40));
    }
}
