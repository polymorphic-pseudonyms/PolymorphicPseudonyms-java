package nl.surfnet.polymorphic;

import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.math.BigInteger;


/**
 * A public key pair.
 */
public class PPKeyPair implements Serializable {
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

    private void writeObject(java.io.ObjectOutputStream out)
            throws IOException {
        out.writeObject(privateKey);
        byte[] encoded = publicKey.getEncoded(false);
        out.writeInt(encoded.length);
        out.write(encoded);
    }
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        privateKey = (BigInteger)in.readObject();
        byte[] encoded = new byte[in.readInt()];
        in.read(encoded);
        publicKey = SystemParams.getCurve().decodePoint(encoded);

    }
    private void readObjectNoData()
            throws ObjectStreamException {
        throw new InvalidObjectException("Stream data needed");
    }
}
