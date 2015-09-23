package nl.surfnet.polymorphic;


/**
 * The Pseudonym Facility creates KDF key D_p and generates encrypted pseudonyms from polymorphic pseudonyms.
 */
public class PF {
    private byte[] Dp;
    private byte[] Dk;

    /**
     * Constructs a new Pseudonym Facility.
     */
    public PF(byte[] Dk) {
        this.Dk = Dk;
        this.Dp = Util.randomBytes(32);
    }

    /**
     * Generate an encrypted pseudonym.
     *
     * @param pp The polymorphic {@link Pseudonym} to create an encrypted pseudonym from
     * @param sp The identifier of the {@link Party} for whom the encrypted pseudonym is destined
     * @return The generated Encrypted {@link Pseudonym}.
     */
    public Pseudonym requestEncryptedPseudonym(Pseudonym pp, String sp) {
        return pp.power(Util.KDF(Dp, sp.getBytes()))
                .keyPower(Util.KDF(Dk, sp.getBytes()))
                .randomize();
    }
}
