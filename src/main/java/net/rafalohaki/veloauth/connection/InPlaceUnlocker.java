package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * Signals the backend the player is already connected to that authentication succeeded.
 * Used only in in-place mode, where the backend is both the auth server and the target.
 *
 * <p>WIP: the payload is not yet signed. Do not deploy until HMAC-SHA256 with a nonce is added
 * and the backend gate verifies it; an unsigned unlock lets any client that can reach the
 * channel unlock itself.
 */
final class InPlaceUnlocker {

    static final MinecraftChannelIdentifier CHANNEL =
            MinecraftChannelIdentifier.create("veloauth", "unlock");

    private final Logger logger;

    InPlaceUnlocker(Logger logger) {
        this.logger = logger;
    }

    boolean unlock(Player player) {
        var server = player.getCurrentServer();
        if (server.isEmpty()) {
            logger.debug("In-place unlock skipped for {}: no current server", player.getUsername());
            return false;
        }
        boolean sent = server.get().sendPluginMessage(CHANNEL, buildPayload(player.getUniqueId()));
        if (!sent) {
            logger.warn("In-place unlock could not be sent to backend for {}", player.getUsername());
        }
        return sent;
    }

    static byte[] buildPayload(UUID uuid) {
        String body = uuid + "|" + Instant.now().getEpochSecond();
        return body.getBytes(StandardCharsets.UTF_8);
    }
}