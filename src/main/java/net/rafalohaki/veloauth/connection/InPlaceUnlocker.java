package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import net.rafalohaki.veloauth.config.Settings;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Signals the backend the player is already connected to that authentication succeeded, and
 * verifies the backend's signed acknowledgement. Used only in in-place mode, where the backend
 * is both the auth server and the target.
 *
 * <p>Protocol v1 (both directions are UTF-8 text, raw bytes with no length prefix, every field
 * covered by an HMAC-SHA256 keyed with auth-server.in-place-secret):
 * <pre>
 *   unlock  proxy -> backend  veloauth:unlock   v1|{uuid}|{epochSeconds}|{nonceHex}|{hmacHex}
 *   ack     backend -> proxy  veloauth:ack      v1|{uuid}|{nonceHex}|{hmacHex}
 * </pre>
 * The HMAC input is a direction label plus the fields ("veloauth-unlock-v1|..." and
 * "veloauth-ack-v1|..."), so a signed unlock can never be replayed back as an ACK or vice
 * versa. Each attempt carries a fresh nonce; the ACK echoes that nonce, which ties it to one
 * specific attempt made on one specific connection.
 *
 * <p>The signature stops a bare-handed client from forging its own unlock (it does not know the
 * key), which is the actual bypass this exists to close; it does not defend against an
 * adversary who can read raw traffic between the proxy process and the backend process, since
 * that channel is unencrypted like any other proxy-to-backend plugin message. Keep proxy and
 * backend on a private network or loopback, the same trust boundary Velocity's own
 * player-info-forwarding secret already assumes.
 */
final class InPlaceUnlocker {

    static final MinecraftChannelIdentifier CHANNEL =
            MinecraftChannelIdentifier.create("veloauth", "unlock");
    static final MinecraftChannelIdentifier ACK_CHANNEL =
            MinecraftChannelIdentifier.create("veloauth", "ack");

    static final String PROTOCOL_VERSION = "v1";
    static final String UNLOCK_LABEL = "veloauth-unlock-v1";
    static final String ACK_LABEL = "veloauth-ack-v1";
    /** Upper bound applied before an ACK is parsed; a legitimate one is well under 200 bytes. */
    static final int MAX_ACK_BYTES = 256;

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Logger logger;
    private final Settings settings;

    InPlaceUnlocker(Logger logger, Settings settings) {
        this.logger = logger;
        this.settings = settings;
    }

    /** One unlock attempt sequence for one connection: its nonces, try count and ACK status. */
    static final class Attempt {
        private final Set<String> nonces = ConcurrentHashMap.newKeySet();
        private final AtomicInteger attemptsMade = new AtomicInteger();
        private final AtomicBoolean acknowledged = new AtomicBoolean();
        private final long startedNanos = System.nanoTime();

        int nextAttemptNumber() {
            return attemptsMade.incrementAndGet();
        }

        int attemptsMade() {
            return attemptsMade.get();
        }

        boolean acknowledged() {
            return acknowledged.get();
        }

        /** @return true only for the call that first marks this sequence acknowledged */
        boolean markAcknowledged() {
            return acknowledged.compareAndSet(false, true);
        }

        long elapsedMillis() {
            return (System.nanoTime() - startedNanos) / 1_000_000L;
        }

        boolean ownsNonce(String nonceHex) {
            return nonces.contains(nonceHex);
        }
    }

    /** A signed unlock message together with the nonce the backend will echo in its ACK. */
    record SignedUnlock(byte[] payload, String nonceHex) {
    }

    /**
     * Sends one signed unlock message (fresh nonce) and registers that nonce on {@code attempt}.
     * A successful send only means the message was accepted for sending - completion is
     * decided solely by a matching ACK.
     */
    boolean unlock(Player player, Attempt attempt) {
        var server = player.getCurrentServer();
        if (server.isEmpty()) {
            logger.debug("In-place unlock skipped for {}: no current server", player.getUsername());
            return false;
        }
        SignedUnlock signed;
        try {
            signed = buildSignedUnlock(player.getUniqueId(), settings.getAuthServerInPlaceSecret());
        } catch (GeneralSecurityException e) {
            // Validated at startup (SettingsValidator), so this should be unreachable in
            // practice. Fail closed rather than sending an unsigned fallback.
            logger.error("In-place unlock signing failed for {}: {}", player.getUsername(), e.toString());
            return false;
        }
        attempt.nonces.add(signed.nonceHex());
        boolean sent = server.get().sendPluginMessage(CHANNEL, signed.payload());
        if (!sent) {
            logger.warn("In-place unlock could not be sent to backend for {}", player.getUsername());
        }
        return sent;
    }

    /**
     * Verifies a backend ACK for {@code player} against {@code attempt}. Every check must
     * pass: size, version, canonical UUID equal to this player's, a nonce this attempt issued,
     * and a valid HMAC. Anything else (forged, stale, malformed, for another connection) is
     * ignored. Never logs the payload.
     */
    boolean acknowledge(Player player, Attempt attempt, byte[] data) {
        if (data == null || data.length > MAX_ACK_BYTES) {
            return false;
        }
        String[] parts = new String(data, StandardCharsets.UTF_8).split("\\|", -1);
        if (parts.length != 4 || !PROTOCOL_VERSION.equals(parts[0])) {
            return false;
        }
        String uuidPart = parts[1];
        String nonceHex = parts[2];
        String signatureHex = parts[3];
        if (!player.getUniqueId().toString().equals(uuidPart) || !attempt.ownsNonce(nonceHex)) {
            return false;
        }
        String expected;
        try {
            expected = hmacHex(settings.getAuthServerInPlaceSecret(),
                    ACK_LABEL + "|" + uuidPart + "|" + nonceHex);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            logger.error("In-place ACK verification failed for {}: {}", player.getUsername(), e.toString());
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                signatureHex.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Builds "v1|{uuid}|{epochSeconds}|{nonceHex}|{hmacHex}". The HMAC covers the direction
     * label, UUID, timestamp and nonce. The nonce also gives the gate mod's replay cache
     * something unique to key on, and lets the ACK be tied to this exact attempt.
     */
    static SignedUnlock buildSignedUnlock(UUID uuid, String secretHex) throws GeneralSecurityException {
        long epochSeconds = Instant.now().getEpochSecond();
        byte[] nonceBytes = new byte[16];
        SECURE_RANDOM.nextBytes(nonceBytes);
        String nonceHex = HexFormat.of().formatHex(nonceBytes);

        String fields = uuid + "|" + epochSeconds + "|" + nonceHex;
        String signatureHex = hmacHex(secretHex, UNLOCK_LABEL + "|" + fields);

        String body = PROTOCOL_VERSION + "|" + fields + "|" + signatureHex;
        return new SignedUnlock(body.getBytes(StandardCharsets.UTF_8), nonceHex);
    }

    private static String hmacHex(String secretHex, String data) throws GeneralSecurityException {
        byte[] key = HexFormat.of().parseHex(secretHex);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(signature);
    }
}
