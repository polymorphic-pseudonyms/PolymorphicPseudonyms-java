package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * An Identity Provider creates polymorphic pseudonyms for its users.
 */
public class IdP {
    private ECPoint y_k;

    /**
     * Construct an Identity Provider.
     *
     * @param y_k The system-wide public key used in the federation
     */
    public IdP(ECPoint y_k){
        this.y_k = y_k;
    }

    /**
     * Generate a polymorphic pseudonym for a specific user.
     *
     * @param uid The User ID of the user for whom a polymorphic pseudonym should be formed
     * @return The Polymorphic {@link Pseudonym} for the user specified by the given uid.
     */
    public Pseudonym generatePolymorphicPseudonym(String uid){
        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();
        encryptor.init(new ECPublicKeyParameters(y_k, SystemParams.getDomainParameters()));
        ECPair pair = encryptor.encrypt(Util.embed(uid.getBytes()));

        return new Pseudonym(
                pair.getX(),
                pair.getY(),
                y_k
        );
    }
}
