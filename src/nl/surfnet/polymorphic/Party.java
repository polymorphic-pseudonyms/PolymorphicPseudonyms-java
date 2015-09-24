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
    private BigInteger cn;

    /**
     * Constructs a Party.
     *
     * @param id The id for this Party
     * @param kma The {@link KMA} of the federation this Party is a part of
     */
    public Party(String id, KMA kma) {
        this.id = id;
        this.keyPair = kma.requestKeyPair(id);
        this.cn = Util.random();
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
        j = j.multiply(cn);
        return Util.Hash(j.getEncoded(false));
    }

    /**
     *
     * @return The public key of this Party
     */
    public ECPoint getPublicKey() {
        return keyPair.getPublicKey();
    }
}
