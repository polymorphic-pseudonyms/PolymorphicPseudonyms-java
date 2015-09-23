package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * The parameters of the curve used in the system.
 */
public class SystemParams {
    private static ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("brainpoolp320r1");

    public static ECCurve getCurve() {
        return spec.getCurve();
    }

    public static ECPoint getG() {
        return spec.getG();
    }

    public static ECDomainParameters getDomainParameters() {
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    public static BigInteger getOrder() {
        return getCurve().getOrder();
    }
}
