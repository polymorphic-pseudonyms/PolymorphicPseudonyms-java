package nl.surfnet.polymorphic;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.math.BigInteger;

/**
 * A triple of {@link ECPoint}s representing either a Polymorphic Pseudonym or an Encrypted Pseudonym.
 *
 * A pseudonym consists of the triple:
 * {@code (A, B, C) = EG(S, y, k) = (g^k, S * y^k, y)}
 * With {@code EG(S, y, k)} being an ElGamal encryption of plaintext {@code S} with public key {@code y}, using random {@code k}.
 *
 * @see IdP#generatePolymorphicPseudonym(String uid)
 * @see PF#requestEncryptedPseudonym(Pseudonym pp, String sp)
 * @see Party#decryptPseudonym(Pseudonym ep)
 */
public class Pseudonym implements Serializable {
    private ECPoint A, B, C;

    /**
     * Construct a pseudonym triple.
     *
     * @param A The first {@link ECPoint} of the triple
     * @param B The second {@link ECPoint} of the triple
     * @param C The third {@link ECPoint} of the triple
     */
    public Pseudonym(ECPoint A, ECPoint B, ECPoint C) {
        this.A = A;
        this.B = B;
        this.C = C;
    }

    /**
     * Transforms a Pseudonym from {@code EG(S, y, k)} to {@code EG(S^z, y, k*z)}
     * @param z The power to exponentiate {@code S} by
     * @return The transformed Pseudonym
     */
    public Pseudonym power(BigInteger z) {
        return new Pseudonym(
                A.multiply(z),
                B.multiply(z),
                C
        );
    }

    /**
     * Transforms a Pseudonym from {@code EG(S, y, k)} to {@code EG(S, y^(z^-1), k*z)}
     * @param z The inverse of the power to exponentiate {@code y} by
     * @return The transformed Pseudonym
     */
    public Pseudonym keyPower(BigInteger z) {
        return new Pseudonym(
                A.multiply(z),
                B,
                C.multiply(z.modInverse(C.getCurve().getOrder()))
        );
    }

    /**
     * Randomizes a Pseudonym from {@code EG(S, y, k)} to {@code EG(S, y, k+z)}
     * @param z The random number to randomize the Pseudnym with
     * @return The randomized Pseudonym
     */
    public Pseudonym randomize(BigInteger z) {
        return new Pseudonym(
                A.add(SystemParams.getG().multiply(z)),
                B.add(C.multiply(z)),
                C
        );
    }

    /**
     * Randomizes a Pseudonym from {@code EG(S, y, k)} to {@code EG(S, y, k+z)}, for a randomly generated {@code z}
     * @return The randomized Pseudonym
     */
    public Pseudonym randomize() {
        return randomize(Util.random());
    }

    /**
     * @return The first {@link ECPoint} of the triple
     */
    public ECPoint getA() {
        return A;
    }

    /**
     * @return The second {@link ECPoint} of the triple
     */
    public ECPoint getB() {
        return B;
    }

    /**
     * @return The second {@link ECPoint} of the triple
     */
    public ECPoint getC() {
        return C;
    }

    @Override
    public String toString() {
        return String.format("(\n\tA: %s\n" +
                "\tB: %s\n" +
                "\tC: %s\n" +
                ")", Hex.toHexString(A.getEncoded(false)),
                Hex.toHexString(B.getEncoded(false)),
                Hex.toHexString(C.getEncoded(false)));
    }

    /**
     * Encode the pseudonym
     * @return The base64 encoding of the encoded points, concatenated with ',' as separator.
     */
    public String encode() {
        return String.format("%s,%s,%s",
                Base64.toBase64String(A.getEncoded(true)),
                Base64.toBase64String(B.getEncoded(true)),
                Base64.toBase64String(C.getEncoded(true)));
    }

    /**
     * Decodes a pseudonym, that is decoded as described for {@link #encode()}
     * @param encoded The encoded pseudonym
     * @return The pseudonym that is decoded from the passed String
     */
    public static Pseudonym decode(String encoded) {
        String[] parts = encoded.split(",");
        if(parts.length != 3) {
            throw new IllegalArgumentException("Encoded string must have 3 parts");
        }
        return new Pseudonym(
                SystemParams.getCurve().decodePoint(Base64.decode(parts[0])),
                SystemParams.getCurve().decodePoint(Base64.decode(parts[1])),
                SystemParams.getCurve().decodePoint(Base64.decode(parts[2]))
        );
    }

    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        writeECPoint(out, A);
        writeECPoint(out, B);
        writeECPoint(out, C);
    }

    private void writeECPoint(ObjectOutputStream out, ECPoint point) throws IOException {
        byte[] encoded = point.getEncoded(false);
        out.writeInt(encoded.length);
        out.write(encoded);
    }

    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        A = readECPoint(in);
        B = readECPoint(in);
        C = readECPoint(in);
    }

    private ECPoint readECPoint(ObjectInputStream in) throws IOException {
        byte[] encoded = new byte[in.readInt()];
        in.read(encoded);
        return SystemParams.getCurve().decodePoint(encoded);
    }

    private void readObjectNoData()
            throws ObjectStreamException {
        throw new InvalidObjectException("Stream data needed");
    }
}
