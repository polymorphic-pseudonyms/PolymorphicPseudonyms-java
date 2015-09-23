package nl.surfnet.polymorphic;


/**
 * Created by Hans on 17-9-2015.
 */
public class PF {
    private byte[] Dp;
    private byte[] Dk;

    public PF() {
        Dp = Util.randomBytes(32);
    }

    public Pseudonym requestEncryptedPseudonym(Pseudonym pp, String sp) {
        return pp.power(Util.KDF(Dp, sp.getBytes()))
                .keyPower(Util.KDF(Dk, sp.getBytes()))
                .randomize();
    }

    public void setDk(byte[] Dk) {
        this.Dk = Dk;
    }
}
