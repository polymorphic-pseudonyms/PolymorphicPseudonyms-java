import nl.surfnet.polymorphic.*;
import org.bouncycastle.util.encoders.Hex;
import org.kohsuke.args4j.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.Scanner;

@SuppressWarnings("unchecked")
public class Main {

    private enum Command {
        GenerateKeys,
        IdP,
        SP,
        All
    }

    private enum CommandArgument {
        Register,
        Authenticate
    }

    @Argument(index = 0, metaVar = "COMMAND", usage = "The command to execute")
    private Command command = Command.All;

    @Argument(index = 1, metaVar = "COMMAND_ARGUMENT", usage = "The argument for the command")
    private CommandArgument commandArgument;

    @Option(name = "-o", metaVar = "OUTPUT", usage = "Write the output to file OUTPUT")
    private File out;

    public static void main(String[] args) {
        new Main().doMain(args);
    }

    public void doMain(String[] args) {
        CmdLineParser parser = new CmdLineParser(this);

        try {
            parser.parseArgument(args);

        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            System.err.println("poly COMMAND [arguments...] [options...]");

            parser.printUsage(System.err);
            System.err.println();

            System.err.println("  Example: poly" + parser.printExample(OptionHandlerFilter.ALL));

            return;
        }

        if(out != null) {
            try {
                System.setOut(new PrintStream(out));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }

        switch (command) {

            case GenerateKeys:
                PPHelper.generateKeys();
                break;
            case IdP:
                Scanner scanner = new Scanner(System.in);
                System.out.print("Username:");
                String uid = scanner.nextLine();
                switch (commandArgument) {
                    case Register:
                        PPHelper.registerUser(uid);
                        break;
                    case Authenticate:
                        System.out.print("SP:");
                        String spid = scanner.nextLine();
                        Pseudonym ep = PPHelper.authenticateUser(uid, spid);
                        System.out.println("Encrypted Pseudonym:");
                        System.out.println(ep);
                        break;
                }
                break;
            case SP:
                scanner = new Scanner(System.in);
                System.out.print("SP:");
                String spid = scanner.nextLine();
                switch (commandArgument) {
                    case Register:
                        PPHelper.registerSP(spid);
                        break;
                    case Authenticate:
                        authenticateSP(spid);
                        break;
                }
                break;
            case All:
                runAll();
                break;
        }
    }



    private void authenticateSP(String spid) {
        System.out.println("Enter the Encrypted Pseudonym:");
        Scanner scanner = new Scanner(System.in);
        String openBracket = scanner.nextLine().trim();
        String A = scanner.nextLine().trim();
        String B = scanner.nextLine().trim();
        String C = scanner.nextLine().trim();
        String closeBracket = scanner.nextLine();
        if(!openBracket.equals("(") || !closeBracket.equals(")") || !A.startsWith("A:") || !B.startsWith("B:") || !C.startsWith("C:")) {
            System.out.println("Incorrect format for Encrypted Pseudonym");
            return;
        }

        byte[] ABytes = Hex.decode(A.substring(2).trim());
        byte[] BBytes = Hex.decode(B.substring(2).trim());
        byte[] CBytes = Hex.decode(C.substring(2).trim());

        Pseudonym ep = new Pseudonym(
                SystemParams.getCurve().decodePoint(ABytes),
                SystemParams.getCurve().decodePoint(BBytes),
                SystemParams.getCurve().decodePoint(CBytes)
        );

        byte[] pseudonym = PPHelper.authenticateSP(spid, ep);
        System.out.printf("Authenticated with pseudonym '%s'\n", Hex.toHexString(pseudonym));
    }

    public void runAll() {
        KMA kma = new KMA();
        PF pf = new PF(kma.getDk());
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
