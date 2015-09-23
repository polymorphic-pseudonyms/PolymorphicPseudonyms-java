package nl.surfnet.polymorphic;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;


/**
 * Created by Hans on 17-9-2015.
 */
public class PPKeyPair {
    private BigInteger privateKey;
    private ECPoint publicKey;

    public PPKeyPair(BigInteger privateKey) {
        this.privateKey = privateKey;
        this.publicKey = SystemParams.getG().multiply(privateKey);
    }

    public BigInteger getPrivateKey(){
        return privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }
}
