package nl.surfnet.polymorphic;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * Created by Hans on 17-9-2015.
 */
public class Pseudonym {
    private ECPoint A, B, C;

    public Pseudonym(ECPoint A, ECPoint B, ECPoint C) {
        this.A = A;
        this.B = B;
        this.C = C;
    }

    public Pseudonym power(BigInteger z) {
        return new Pseudonym(
                A.multiply(z),
                B.multiply(z),
                C
        );
    }

    public Pseudonym keyPower(BigInteger z) {
        return new Pseudonym(
                A.multiply(z),
                B,
                C.multiply(z.modInverse(C.getCurve().getOrder()))
        );
    }

    public Pseudonym randomize(BigInteger z) {
        return new Pseudonym(
                A.add(SystemParams.getG().multiply(z)),
                B.add(C.multiply(z)),
                C
        );
    }

    public Pseudonym randomize() {
        return randomize(Util.random());
    }

    public ECPoint getA() {
        return A;
    }

    public ECPoint getB() {
        return B;
    }

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
}
