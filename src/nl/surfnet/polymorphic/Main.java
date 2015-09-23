package nl.surfnet.polymorphic;

import org.bouncycastle.util.encoders.Hex;

public class Main {

    public static void main(String[] args) {

        PF pf = new PF();
        KMA kma = new KMA(pf);
        System.out.printf("y_k: %s\n", Hex.toHexString(kma.getY_k().getEncoded(false)));
        IdP idp = new IdP("ru.nl", kma);
        Party sp = new Party("google.nl", kma);
        System.out.printf("google.nl public key: %s\n\n", Hex.toHexString(sp.getPublicKey().getEncoded(false)));

        for(int i =0; i < 3; i++) {
            Pseudonym pp = idp.generatePolymorphicPseudonym("j.harmannij");
            System.out.printf("PP:\n%s\n\n", pp);
            for(int j = 0; j < 2; j++) {
                Pseudonym ep = pf.requestEncryptedPseudonym(pp, "google.nl");
                byte[] p = sp.decryptPseudonym(ep);

                System.out.printf("EP:\n%s\n\nPseudonym:\n%s\n=============\n\n", ep, Hex.toHexString(p));
            }
        }


    }
}
