package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by Hans on 21-9-2015.
 */
public class Party {
    private String id;
    private PPKeyPair keyPair;
    private BigInteger cn;

    public Party(String id, KMA kma) {
        this.id = id;
        this.keyPair = kma.requestKeyPair(id);
        this.cn = Util.random();
    }

    public byte[] decryptPseudonym(Pseudonym ep) {
        ECElGamalDecryptor decryptor = new ECElGamalDecryptor();
        decryptor.init(new ECPrivateKeyParameters(keyPair.getPrivateKey(), SystemParams.getDomainParameters()));
        ECPoint j = decryptor.decrypt(new ECPair(ep.getA(), ep.getB()));
        j = j.multiply(cn);
        return Util.Hash(j.getEncoded(false));
    }

    public ECPoint getPublicKey() {
        return keyPair.getPublicKey();
    }
}
