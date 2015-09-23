package nl.surfnet.polymorphic;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Created by Hans on 21-9-2015.
 */
public class IdP extends Party {
    KMA kma;

    public IdP(String id, KMA kma){
        super(id, kma);
        this.kma = kma;
    }

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
