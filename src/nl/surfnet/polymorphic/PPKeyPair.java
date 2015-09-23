package nl.surfnet.polymorphic;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;


/**
 * A public key pair.
 */
public class PPKeyPair {
    private BigInteger privateKey;
    private ECPoint publicKey;

    /**
     * Construct a new public key pair. The public key is generated from the private key.
     * @param privateKey The private key of this key pair.
     */
    public PPKeyPair(BigInteger privateKey) {
        this.privateKey = privateKey;
        this.publicKey = SystemParams.getG().multiply(privateKey);
    }

    /**
     *
     * @return the private key in this key pair
     */
    public BigInteger getPrivateKey(){
        return privateKey;
    }

    /**
     *
     * @return the public key in this key pair
     */
    public ECPoint getPublicKey() {
        return publicKey;
    }
}
