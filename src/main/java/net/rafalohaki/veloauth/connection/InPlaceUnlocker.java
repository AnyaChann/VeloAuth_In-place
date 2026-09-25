package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import net.rafalohaki.veloauth.config.Settings;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Signals the backend the player is already connected to that authentication succeeded.
 * Used only in in-place mode, where the backend is both the auth server and the target.
 *
 * <p>The payload is HMAC-SHA256-signed with a key shared out-of-band with the backend gate
 * mod's own config (auth-server.in-place-secret / the gate mod's "secret" setting). Without a
 * matching key, the backend must reject the unlock - see the gate mod's verification code.
 * This signature stops a bare-handed client from forging its own unlock (it does not know the
 * key), which is the actual bypass this exists to close; it does not defend against an
 * adversary who can read raw traffic between the proxy process and the backend process, since
 * that channel is unencrypted like any other proxy-to-backend plugin message. Keep proxy and
 * backend on a private network or loopback, the same trust boundary Velocity's own
 * player-info-forwarding secret already assumes.
 */
final class InPlaceUnlocker {

    static final MinecraftChannelIdentifier CHANNEL =
            MinecraftChannelIdentifier.create("veloauth", "unlock");

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Logger logger;
    private final Settings settings;

    InPlaceUnlocker(Logger logger, Settings settings) {
        this.logger = logger;
        this.settings = settings;
    }

    boolean unlock(Player player) {
        var server = player.getCurrentServer();
        if (server.isEmpty()) {
            logger.debug("In-place unlock skipped for {}: no current server", player.getUsername());
            return false;
        }
        byte[] payload;
        try {
            payload = buildSignedPayload(player.getUniqueId(), settings.getAuthServerInPlaceSecret());
        } catch (GeneralSecurityException e) {
            // Validated at startup (SettingsValidator), so this should be unreachable in
            // practice. Fail closed rather than sending an unsigned fallback.
            logger.error("In-place unlock signing failed for {}: {}", player.getUsername(), e.toString());
            return false;
        }
        boolean sent = server.get().sendPluginMessage(CHANNEL, payload);
        if (!sent) {
            logger.warn("In-place unlock could not be sent to backend for {}", player.getUsername());
        }
        return sent;
    }

    /**
     * Wire format: UTF-8 "{uuid}|{epochSeconds}|{nonceHex}|{hmacHex}", entirely raw bytes with
     * no length prefix (ServerConnection#sendPluginMessage sends exactly these bytes and
     * nothing else - see UnlockPayload on the gate-mod side for why a length-prefixed codec is
     * wrong here). The nonce gives the gate mod's replay cache something unique to key on even
     * when two unlocks for the same player land in the same second.
     */
    static byte[] buildSignedPayload(UUID uuid, String secretHex) throws GeneralSecurityException {
        long epochSeconds = Instant.now().getEpochSecond();
        byte[] nonceBytes = new byte[16];
        SECURE_RANDOM.nextBytes(nonceBytes);
        String nonceHex = HexFormat.of().formatHex(nonceBytes);

        String signedPart = uuid + "|" + epochSeconds + "|" + nonceHex;
        String signatureHex = hmacHex(secretHex, signedPart);

        String body = signedPart + "|" + signatureHex;
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static String hmacHex(String secretHex, String data) throws GeneralSecurityException {
        byte[] key = HexFormat.of().parseHex(secretHex);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(signature);
    }
}