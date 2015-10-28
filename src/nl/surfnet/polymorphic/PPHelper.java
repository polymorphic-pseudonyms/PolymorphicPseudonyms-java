package nl.surfnet.polymorphic;

import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by Hans on 1-10-2015.
 */
public class PPHelper {
    public static byte[] authenticateSP(String spid, Pseudonym ep) {
        HashMap<String, Party> sps = loadSPs();
        if(sps == null) {
            return null;
        }

        if(!sps.containsKey(spid)) {
            System.err.printf("SP '%s' is not registered\n", spid);
            return null;
        }

        Party sp = sps.get(spid);

        return sp.decryptPseudonym(ep);
    }

    public static void registerSP(String spid) {
        HashMap<String, Party> sps = loadSPs();
        if(sps == null) {
            return;
        }

        if(sps.containsKey(spid)) {
            System.err.printf("SP '%s' already registered\n", spid);
            return;
        }

        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("kma"));
            KMA kma = (KMA) ois.readObject();
            ois.close();

            PPKeyPair keyPair = kma.requestKeyPair(spid);
            BigInteger closingKey = Util.random();
            Party party = new Party(spid, keyPair, closingKey);
            sps.put(spid, party);

            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("SPs"));
            oos.writeObject(sps);
            oos.close();
            System.out.printf("SP '%s' successfully registered\n", spid);

            System.out.printf("public key:\n%s\nprivate key:\n%s\nclosing key:\n%s\n",
                    Base64.toBase64String(keyPair.getPublicKey().getEncoded(true)),
                    Base64.toBase64String(keyPair.getPrivateKey().toByteArray()),
                    Base64.toBase64String(closingKey.toByteArray()));
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static Pseudonym authenticateUser(String uid, String spid) {
        HashMap<String, Pseudonym> users = loadUsers();
        if(users == null) {
            return null;
        }

        if(!users.containsKey(uid)) {
            System.err.printf("User '%s' is not registered\n", uid);
            return null;
        }

        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("pf"));
            PF pf = (PF) ois.readObject();
            ois.close();

            return pf.requestEncryptedPseudonym(users.get(uid), spid);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void registerUser(String uid) {
        HashMap<String, Pseudonym> users = loadUsers();
        if(users == null) {
            return;
        }

        if(users.containsKey(uid)) {
            System.err.printf("User '%s' already registered\n", uid);
            return;
        }

        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("kma"));
            KMA kma = (KMA) ois.readObject();
            ois.close();

            IdP idp = new IdP(kma.getY_k());
            Pseudonym pp = idp.generatePolymorphicPseudonym(uid);
            users.put(uid, pp);

            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("users"));
            oos.writeObject(users);
            oos.close();

            System.out.printf("User '%s' registered with Polymorphic Pseudonym\n%s", uid, pp.encode());
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static HashMap<String, Pseudonym> loadUsers() {
        HashMap<String, Pseudonym> users = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("users"));
            users = (HashMap<String, Pseudonym>) ois.readObject();
            ois.close();
        } catch (FileNotFoundException e) {
            users = new HashMap<>();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return users;
    }

    public static HashMap<String, Party> loadSPs() {
        HashMap<String, Party> sps = null;
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("SPs"));
            sps = (HashMap<String, Party>) ois.readObject();
            ois.close();
        } catch (FileNotFoundException e) {
            sps = new HashMap<>();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return sps;
    }

    public static void generateKeys() {
        KMA kma = new KMA();
        byte[] dp = Util.randomBytes(32);
        PF pf = new PF(kma.getDk(), dp);

        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("kma"));
            oos.writeObject(kma);
            oos.close();
            System.out.println("KMA keys generated");

            oos = new ObjectOutputStream(new FileOutputStream(new File("pf")));
            oos.writeObject(pf);
            oos.close();
            System.out.println("PF keys generated");
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.printf("dp: %s\ndk: %s\ny_k: %s\n\n", Base64.toBase64String(dp), Base64.toBase64String(kma.getDk()), Base64.toBase64String(kma.getY_k().getEncoded(true)));
    }
}
