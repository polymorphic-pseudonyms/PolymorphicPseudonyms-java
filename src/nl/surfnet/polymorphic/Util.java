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
 * Created by Hans on 17-9-2015.
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
    public static BigInteger KDF(byte[] k, byte[] data) {
        try {
            Mac hMac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(k, "HmacSHA256");
            hMac.init(key);
            byte[] bytes = hMac.doFinal(data);
            return new BigInteger(1, bytes);
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] Hash(byte[] data) {
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(data, 0, data.length);
        byte[] out = new byte[sha256.getDigestSize()];
        sha256.doFinal(out, 0);
        return out;
    }

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

    public static byte[] randomBytes(int num) {
        byte[] bytes = new byte[num];
        prng.nextBytes(bytes);
        return bytes;
    }

    public static BigInteger random() {
        return new BigInteger(randomBytes(40));
    }
}
