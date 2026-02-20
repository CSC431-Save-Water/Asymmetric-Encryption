import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.*;
import java.util.Base64;
import java.io.*;
import java.nio.file.*;

/**
 * AsymmetricEncryption.java
 *
 * Demonstrates RSA-based asymmetric encryption and decryption in Java.
 *
 * Features:
 *   - 2048-bit RSA key pair generation
 *   - Encrypt plaintext with the public key (OAEP/SHA-256 padding)
 *   - Decrypt ciphertext with the private key
 *   - Output displayed in Base64 format
 *   - Robust error handling (empty input, oversized input, bad ciphertext)
 *   - [Extra Credit] Save / load keys to/from disk files
 *   - [Extra Credit] Digital signature creation and verification
 *   - Three automated test cases accessible from the menu
 *
 * Dependencies: Standard Java SE (no third-party libraries required)
 * Compile: javac AsymmetricEncryption.java
 * Run:     java AsymmetricEncryption
 */
public class AsymmetricEncryption {

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /** RSA key size in bits. 2048 is the minimum recommended size. */
    private static final int KEY_SIZE = 2048;

    /** Base algorithm name used for key generation and KeyFactory. */
    private static final String ALGORITHM = "RSA";

    /**
     * Full cipher transformation string.
     * RSA/ECB/OAEPWithSHA-256AndMGF1Padding is recommended over the older
     * PKCS1Padding because it is resistant to chosen-ciphertext attacks.
     */
    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /** Signature algorithm used for optional digital-signature features. */
    private static final String SIG_ALGORITHM = "SHA256withRSA";

    /** File name for the saved public key (DER/X.509 format). */
    private static final String PUBLIC_KEY_FILE = "public_key.der";

    /** File name for the saved private key (DER/PKCS8 format). */
    private static final String PRIVATE_KEY_FILE = "private_key.der";

    /**
     * Maximum plaintext size in bytes for a 2048-bit key with OAEP SHA-256.
     * Formula: keyBytes - 2*hLen - 2 = 256 - 64 - 2 = 190 bytes.
     */
    private static final int MAX_PLAINTEXT_BYTES = 190;

    // -----------------------------------------------------------------------
    // Instance fields
    // -----------------------------------------------------------------------

    /** The RSA public key used for encryption and signature verification. */
    private PublicKey publicKey;

    /** The RSA private key used for decryption and signing. */
    private PrivateKey privateKey;

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /**
     * Generates a fresh 2048-bit RSA key pair and stores both keys in memory.
     * Previous keys (if any) are replaced.
     *
     * @throws NoSuchAlgorithmException if RSA is unavailable in this JVM
     */
    public void generateKeys() throws NoSuchAlgorithmException {
        System.out.println("Generating 2048-bit RSA key pair...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        // SecureRandom provides cryptographically strong randomness
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        this.publicKey  = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        System.out.println("Key pair generated successfully.");
    }

    /**
     * [Extra Credit] Saves the current public and private keys to disk.
     * Public key is written in X.509/DER format; private key in PKCS8/DER format.
     * These formats are directly loadable by Java's KeyFactory.
     *
     * @throws IOException if a file cannot be written
     */
    public void saveKeys() throws IOException {
        Files.write(Paths.get(PUBLIC_KEY_FILE),  publicKey.getEncoded());
        Files.write(Paths.get(PRIVATE_KEY_FILE), privateKey.getEncoded());
        System.out.println("Public key saved  -> " + PUBLIC_KEY_FILE);
        System.out.println("Private key saved -> " + PRIVATE_KEY_FILE);
    }

    /**
     * [Extra Credit] Loads previously saved public and private keys from disk.
     * The public key is read as an X.509 spec; the private key as a PKCS8 spec.
     *
     * @throws Exception if a file is missing, corrupted, or cannot be parsed
     */
    public void loadKeys() throws Exception {
        byte[] pubBytes  = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
        byte[] privBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        this.publicKey  = keyFactory.generatePublic( new X509EncodedKeySpec(pubBytes));
        this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        System.out.println("Keys loaded from disk successfully.");
    }

    /**
     * Returns true if both key files already exist on disk.
     * Used at startup to offer the user a choice to reuse saved keys.
     */
    public boolean keysExistOnDisk() {
        return Files.exists(Paths.get(PUBLIC_KEY_FILE))
            && Files.exists(Paths.get(PRIVATE_KEY_FILE));
    }

    // -----------------------------------------------------------------------
    // Encryption and decryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts a plaintext string with the RSA public key and returns the
     * result as a Base64-encoded string.
     *
     * Padding scheme: OAEP with SHA-256 hash and MGF1 mask-generation function.
     *
     * @param plaintext the message to encrypt (UTF-8, max 190 bytes)
     * @return Base64-encoded ciphertext
     * @throws IllegalArgumentException if the input is null, empty, or too large
     * @throws Exception for any underlying cryptographic failure
     */
    public String encrypt(String plaintext) throws Exception {
        // --- Input validation ---
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Plaintext message cannot be empty.");
        }

        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        if (plaintextBytes.length > MAX_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException(
                "Plaintext is too large for direct RSA encryption. "
                + "Maximum size: " + MAX_PLAINTEXT_BYTES + " bytes, "
                + "your input: "  + plaintextBytes.length + " bytes. "
                + "Consider splitting the message or using hybrid encryption."
            );
        }

        // --- Encrypt with public key ---
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintextBytes);

        // Encode as Base64 so the ciphertext is printable
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts a Base64-encoded RSA ciphertext with the private key and
     * returns the original plaintext string.
     *
     * @param ciphertext Base64-encoded ciphertext produced by {@link #encrypt}
     * @return original plaintext string
     * @throws IllegalArgumentException if the ciphertext is null or empty
     * @throws Exception for any cryptographic failure (e.g., wrong key, corrupted data)
     */
    public String decrypt(String ciphertext) throws Exception {
        // --- Input validation ---
        if (ciphertext == null || ciphertext.isEmpty()) {
            throw new IllegalArgumentException("Ciphertext cannot be empty.");
        }

        // Decode the Base64 representation back to raw bytes
        byte[] ciphertextBytes;
        try {
            ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Ciphertext is not valid Base64. Please paste the output exactly as shown."
            );
        }

        // --- Decrypt with private key ---
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);

        return new String(decryptedBytes, "UTF-8");
    }

    // -----------------------------------------------------------------------
    // Digital signatures (Extra Credit)
    // -----------------------------------------------------------------------

    /**
     * [Extra Credit] Creates a digital signature for a message using the
     * private key. The signature can later be verified with the public key.
     *
     * Algorithm: SHA-256 with RSA (SHA256withRSA)
     *
     * @param message the message to sign
     * @return Base64-encoded digital signature
     * @throws Exception for any signing failure
     */
    public String sign(String message) throws Exception {
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("Message to sign cannot be empty.");
        }
        Signature sig = Signature.getInstance(SIG_ALGORITHM);
        sig.initSign(privateKey);
        sig.update(message.getBytes("UTF-8"));
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * [Extra Credit] Verifies a digital signature against the original message
     * using the public key.
     *
     * @param message   the original (unsigned) message text
     * @param signature Base64-encoded signature produced by {@link #sign}
     * @return true if the signature is authentic and unaltered; false otherwise
     * @throws Exception for any verification failure
     */
    public boolean verify(String message, String signature) throws Exception {
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("Message cannot be empty.");
        }
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(signature.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Signature is not valid Base64.");
        }
        Signature sig = Signature.getInstance(SIG_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message.getBytes("UTF-8"));
        return sig.verify(signatureBytes);
    }

    // -----------------------------------------------------------------------
    // Automated test cases
    // -----------------------------------------------------------------------

    /**
     * Runs three automated test cases covering basic, sentence-length, and
     * special-character inputs. Each test encrypts a known message and then
     * decrypts it, verifying the result matches the original.
     *
     * Test Case 1: Short greeting (simple ASCII)
     * Test Case 2: Medium-length sentence (typical use case)
     * Test Case 3: Special characters, digits, and punctuation
     *
     * @throws Exception if any cryptographic operation fails
     */
    public void runTests() throws Exception {
        System.out.println("\n========================================");
        System.out.println("        AUTOMATED TEST CASES");
        System.out.println("========================================\n");

        // Three representative test messages
        String[] testMessages = {
            "Hello, World!",
            "RSA encryption is a cornerstone of modern cybersecurity.",
            "Special chars: !@#$%^&*()_+ and numbers 1234567890."
        };

        int passed = 0;
        for (int i = 0; i < testMessages.length; i++) {
            String label = "Test Case " + (i + 1);
            System.out.println("--- " + label + " ---");
            System.out.println("Input    : " + testMessages[i]);

            try {
                // Encrypt the plaintext
                String encrypted = encrypt(testMessages[i]);
                System.out.println("Encrypted: " + encrypted);

                // Decrypt and verify correctness
                String decrypted = decrypt(encrypted);
                System.out.println("Decrypted: " + decrypted);

                boolean match = testMessages[i].equals(decrypted);
                System.out.println("Result   : " + (match ? "PASS" : "FAIL"));
                if (match) passed++;
            } catch (Exception e) {
                System.out.println("Result   : FAIL - " + e.getMessage());
            }
            System.out.println();
        }

        System.out.println("Passed: " + passed + "/" + testMessages.length);
        System.out.println("========================================\n");
    }

    // -----------------------------------------------------------------------
    // Main method – interactive menu
    // -----------------------------------------------------------------------

    /**
     * Entry point. Presents a menu-driven interface for key management,
     * encryption, decryption, digital signatures, and automated testing.
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {
        AsymmetricEncryption app = new AsymmetricEncryption();
        Scanner scanner = new Scanner(System.in);
        boolean keysReady = false;

        System.out.println("==============================================");
        System.out.println("  Asymmetric Encryption Demo (RSA-2048)");
        System.out.println("==============================================\n");

        // --- Offer to load existing keys from disk (extra credit feature) ---
        if (app.keysExistOnDisk()) {
            System.out.print("Saved key files found. Load them? (y/n): ");
            if (scanner.nextLine().trim().equalsIgnoreCase("y")) {
                try {
                    app.loadKeys();
                    keysReady = true;
                } catch (Exception e) {
                    System.out.println("Could not load keys: " + e.getMessage());
                    System.out.println("Generating new keys instead...\n");
                }
            }
        }

        // --- Generate a new key pair if keys are not yet ready ---
        if (!keysReady) {
            try {
                app.generateKeys();
                keysReady = true;
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Fatal: RSA not available - " + e.getMessage());
                scanner.close();
                return;
            }

            // Offer to persist the newly generated keys to disk
            System.out.print("Save keys to disk for future runs? (y/n): ");
            if (scanner.nextLine().trim().equalsIgnoreCase("y")) {
                try {
                    app.saveKeys();
                } catch (IOException e) {
                    System.out.println("Warning: Could not save keys - " + e.getMessage());
                }
            }
        }

        // --- Main menu loop ---
        boolean running = true;
        while (running) {
            System.out.println("\n----------- Menu -----------");
            System.out.println("1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Encrypt then decrypt (round-trip)");
            System.out.println("4. Sign a message        [Extra Credit]");
            System.out.println("5. Verify a signature    [Extra Credit]");
            System.out.println("6. Run automated tests");
            System.out.println("7. Regenerate key pair");
            System.out.println("8. Exit");
            System.out.print("Choose an option (1-8): ");

            String option = scanner.nextLine().trim();

            switch (option) {

                // ---- Option 1: Encrypt ----
                case "1":
                    System.out.print("Enter plaintext to encrypt: ");
                    String toEncrypt = scanner.nextLine();
                    try {
                        String encrypted = app.encrypt(toEncrypt);
                        System.out.println("\nEncrypted (Base64):");
                        System.out.println(encrypted);
                    } catch (IllegalArgumentException e) {
                        System.out.println("Input error: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Encryption failed: " + e.getMessage());
                    }
                    break;

                // ---- Option 2: Decrypt ----
                case "2":
                    System.out.print("Enter Base64 ciphertext to decrypt: ");
                    String toDecrypt = scanner.nextLine().trim();
                    try {
                        String decrypted = app.decrypt(toDecrypt);
                        System.out.println("\nDecrypted plaintext:");
                        System.out.println(decrypted);
                    } catch (IllegalArgumentException e) {
                        System.out.println("Input error: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Decryption failed. "
                            + "Ensure the ciphertext is valid Base64 from the current key pair.");
                    }
                    break;

                // ---- Option 3: Round-trip ----
                case "3":
                    System.out.print("Enter plaintext for round-trip: ");
                    String roundTrip = scanner.nextLine();
                    try {
                        System.out.println("\nOriginal : " + roundTrip);
                        String enc = app.encrypt(roundTrip);
                        System.out.println("Encrypted: " + enc);
                        String dec = app.decrypt(enc);
                        System.out.println("Decrypted: " + dec);
                        System.out.println("Match    : " + roundTrip.equals(dec));
                    } catch (IllegalArgumentException e) {
                        System.out.println("Input error: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Error during round-trip: " + e.getMessage());
                    }
                    break;

                // ---- Option 4: Sign (Extra Credit) ----
                case "4":
                    System.out.print("Enter message to sign: ");
                    String toSign = scanner.nextLine();
                    try {
                        String signature = app.sign(toSign);
                        System.out.println("\nSignature (Base64):");
                        System.out.println(signature);
                    } catch (IllegalArgumentException e) {
                        System.out.println("Input error: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Signing failed: " + e.getMessage());
                    }
                    break;

                // ---- Option 5: Verify signature (Extra Credit) ----
                case "5":
                    System.out.print("Enter the original message: ");
                    String origMsg = scanner.nextLine();
                    System.out.print("Enter the Base64 signature : ");
                    String sigInput = scanner.nextLine().trim();
                    try {
                        boolean valid = app.verify(origMsg, sigInput);
                        System.out.println("\nSignature is " + (valid ? "VALID." : "INVALID."));
                    } catch (IllegalArgumentException e) {
                        System.out.println("Input error: " + e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Verification failed: " + e.getMessage());
                    }
                    break;

                // ---- Option 6: Automated tests ----
                case "6":
                    try {
                        app.runTests();
                    } catch (Exception e) {
                        System.out.println("Test suite error: " + e.getMessage());
                    }
                    break;

                // ---- Option 7: Regenerate keys ----
                case "7":
                    try {
                        app.generateKeys();
                        System.out.print("Save new keys to disk? (y/n): ");
                        if (scanner.nextLine().trim().equalsIgnoreCase("y")) {
                            app.saveKeys();
                        }
                    } catch (Exception e) {
                        System.out.println("Error regenerating keys: " + e.getMessage());
                    }
                    break;

                // ---- Option 8: Exit ----
                case "8":
                    running = false;
                    System.out.println("Goodbye!");
                    break;

                default:
                    System.out.println("Invalid option. Please enter a number from 1 to 8.");
            }
        }

        scanner.close();
    }
}
