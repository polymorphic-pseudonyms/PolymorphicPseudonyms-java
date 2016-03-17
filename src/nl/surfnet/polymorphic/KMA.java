package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class performs the tasks from the Key Management Authority.
 * It creates a system-wide public key pair, KDF key D_k and public key pairs for all parties in the system.
 */
public class KMA implements Serializable {
    private BigInteger x_k;
    private ECPoint y_k;
    private byte[] Dk;

    /**
     * Construct a KMA. This will generate the system-wide public key pair and KDF key D_k
     */
    public KMA() {
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
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Construct a KMA, with the given keys
     * @param x_k The private key of the system-wide public key pair
     * @param Dk The KDF key D_k
     */
    public KMA(BigInteger x_k, byte[] Dk) {
        this.x_k = x_k;
        this.Dk = Dk;
    }

    /**
     * Lets the {@linkplain Party parties} in the system get their public key pair.
     * @param id The id of the party that requests the key pair
     * @return a {@link PPKeyPair}, containing the private and public key for the requesting party.
     */
    public PPKeyPair requestKeyPair(String id) {
        BigInteger m = Util.KDF(Dk, id.getBytes());
        assert m != null;
        BigInteger x = x_k.multiply(m.modInverse(SystemParams.getOrder())).mod(SystemParams.getOrder());

        return new PPKeyPair(x);
    }

    /**
     *
     * @return the system wide public key
     */
    public ECPoint getY_k() {
        return y_k;
    }

    /**
     *
     * @return the KDF key D_k
     */
    public byte[] getDk() {
        return Dk;
    }

    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        out.writeObject(x_k);
        byte[] encoded = y_k.getEncoded(false);
        out.writeInt(encoded.length);
        out.write(encoded);
        out.writeInt(Dk.length);
        out.write(Dk);

    }
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        x_k = (BigInteger)in.readObject();
        byte[] encoded = new byte[in.readInt()];
        in.read(encoded);
        y_k = SystemParams.getCurve().decodePoint(encoded);
        Dk = new byte[in.readInt()];
        in.read(Dk);

    }
    private void readObjectNoData()
            throws ObjectStreamException {
        throw new InvalidObjectException("Stream data needed");
    }
}
