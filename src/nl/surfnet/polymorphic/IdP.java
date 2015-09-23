package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * An Identity Provider creates polymorphic pseudonyms for its users.
 */
public class IdP extends Party {
    private KMA kma;

    /**
     * Construct an Identity Provider.
     *
     * @param id The id for this {@link Party}
     * @param kma The {@link KMA} of the federation this IdP is part of
     */
    public IdP(String id, KMA kma){
        super(id, kma);
        this.kma = kma;
    }

    /**
     * Generate a polymorphic pseudonym for a specific user.
     *
     * @param uid The User ID of the user for whom a polymorphic pseudonym should be formed
     * @return The Polymorphic {@link Pseudonym} for the user specified by the given uid.
     */
    public Pseudonym generatePolymorphicPseudonym(String uid){
        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();
        encryptor.init(new ECPublicKeyParameters(kma.getY_k(), SystemParams.getDomainParameters()));
        ECPair pair = encryptor.encrypt(Util.embed(uid.getBytes()));

        return new Pseudonym(
                pair.getX(),
                pair.getY(),
                kma.getY_k()
        );
    }
}
