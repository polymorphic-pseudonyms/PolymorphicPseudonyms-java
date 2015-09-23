package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by Hans on 17-9-2015.
 */
public class KMA {
    private BigInteger x_k;
    private ECPoint y_k;
    private byte[] Dk;

    public KMA(PF pf) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        try {
            SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
            generator.init(new ECKeyGenerationParameters(
                    SystemParams.getDomainParameters(),
                    prng));

            AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
            this.x_k = ((ECPrivateKeyParameters) keypair.getPrivate()).getD();
            this.y_k = ((ECPublicKeyParameters) keypair.getPublic()).getQ();

            Dk = Util.randomBytes(32);
            pf.setDk(Dk);
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public PPKeyPair requestKeyPair(String id) {
        BigInteger m = Util.KDF(Dk, id.getBytes());
        BigInteger x = x_k.multiply(m.modInverse(SystemParams.getOrder())).mod(SystemParams.getOrder());

        return new PPKeyPair(x);
    }

    public ECPoint getY_k() {
        return y_k;
    }
}
