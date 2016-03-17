package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.io.Serializable;
import java.math.BigInteger;

/**
 *  A party in the federation. Parties can receive encrypted pseudonyms.
 */
public class Party implements Serializable {
    private String id;
    private PPKeyPair keyPair;
    private BigInteger closingKey;

    /**
     * Constructs a Party.
     *
     * @param id The id for this Party
     * @param keyPair The {@link PPKeyPair} with the public and private key for this Party
     * @param closingKey The closing key this Party uses to form the final pseudonym for its users
     */
    public Party(String id, PPKeyPair keyPair, BigInteger closingKey) {
        this.id = id;
        this.keyPair = keyPair;
        this.closingKey = closingKey;
    }

    /**
     * Decrypt an Encrypted Pseudonym.
     *
     * @param ep The Encrypted {@link Pseudonym}
     * @return The pseudonym from the Encrypted Pseudonym
     */
    public byte[] decryptPseudonym(Pseudonym ep) {
        ECElGamalDecryptor decryptor = new ECElGamalDecryptor();
        decryptor.init(new ECPrivateKeyParameters(keyPair.getPrivateKey(), SystemParams.getDomainParameters()));
        ECPoint j = decryptor.decrypt(new ECPair(ep.getA(), ep.getB()));
        j = j.multiply(closingKey);
        return Util.Hash(j.getEncoded(false));
    }

    /**
     *
     * @return The public key of this Party
     */
    public ECPoint getPublicKey() {
        return keyPair.getPublicKey();
    }

    public BigInteger getPrivateKey() { return keyPair.getPrivateKey(); }

    public BigInteger getClosingKey() { return keyPair.getPrivateKey(); }
}
