package net.rafalohaki.veloauth.command;

import net.kyori.adventure.key.Key;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * EXPERIMENTAL - DO NOT USE IN PRODUCTION. See SessionCookieListener's class Javadoc for the
 * known live-server issue (players get kicked with
 * multiplayer.disconnect.unexpected_query_response on at least one modded backend). This
 * class's own token format/crypto is not implicated - the failure is at the Velocity cookie
 * protocol layer, not here - but the feature as a whole must stay disabled until that is
 * resolved.
 *
 * Builds and verifies the "remember me" session cookie for cracked/offline accounts.
 *
 * <p>Unlike net.rafalohaki.veloauth.connection.InPlaceUnlocker's one-time unlock signal, this
 * token is a reusable bearer credential: the same cookie must keep verifying across many
 * reconnects until it expires, so there is no nonce/replay-guard here - replay IS the intended
 * behavior within the TTL window. Revocation instead rides on the account's own password hash:
 * the hash is mixed into the signed material but never transmitted in the payload, so changing
 * the password automatically invalidates every cookie issued before the change, with no extra
 * server-side revocation list to maintain.
 *
 * <p>Wire format: UTF-8 {@code "{uuid}|{expiryEpochSeconds}|{hmacHex}"}, exactly the raw bytes
 * Velocity's Player#storeCookie/CookieReceiveEvent carry - no length prefix (see
 * InPlaceUnlocker's Javadoc for why a length-prefixed codec would be wrong for this transport).
 */
final class SessionCookieCodec {

    static final Key COOKIE_KEY = Key.key("veloauth", "session");

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private SessionCookieCodec() {
    }

    static byte[] buildToken(UUID uuid, int ttlHours, String passwordHash, String secretHex)
            throws GeneralSecurityException {
        long expiryEpochSeconds = Instant.now().getEpochSecond() + (long) ttlHours * 3600L;
        String signedPart = uuid + "|" + expiryEpochSeconds;
        String signatureHex = hmacHex(secretHex, signedPart, passwordHash);
        return (signedPart + "|" + signatureHex).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Verifies a cookie against the account's CURRENT password hash. Returns the UUID encoded
     * in the cookie only if the signature, expiry, and UUID-match (against {@code expectedId})
     * all pass; returns empty on any malformed, expired, forged, or stale (password since
     * changed) cookie. A verification failure here must never be treated as a failed login
     * attempt - an absent or expired cookie is the ordinary case for most connections, not a
     * credential-guessing signal, so callers must not feed this into brute-force counters.
     */
    static Optional<UUID> verifyToken(byte[] data, UUID expectedId, String passwordHash, String secretHex) {
        String body = new String(data, StandardCharsets.UTF_8);
        String[] parts = body.split("\\|");
        if (parts.length != 3) {
            return Optional.empty();
        }
        UUID id;
        long expiryEpochSeconds;
        try {
            id = UUID.fromString(parts[0]);
            expiryEpochSeconds = Long.parseLong(parts[1]);
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
        if (!id.equals(expectedId)) {
            return Optional.empty();
        }
        if (Instant.now().getEpochSecond() > expiryEpochSeconds) {
            return Optional.empty();
        }
        String signedPart = parts[0] + "|" + parts[1];
        String expectedSignature;
        try {
            expectedSignature = hmacHex(secretHex, signedPart, passwordHash);
        } catch (GeneralSecurityException e) {
            return Optional.empty();
        }
        // Constant-time comparison: an early-exit compare would leak how many leading hex
        // characters of the signature an attacker guessed correctly.
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.US_ASCII),
                parts[2].getBytes(StandardCharsets.US_ASCII))) {
            return Optional.empty();
        }
        return Optional.of(id);
    }

    private static String hmacHex(String secretHex, String signedPart, String passwordHash)
            throws GeneralSecurityException {
        byte[] key = HexFormat.of().parseHex(secretHex);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        // passwordHash is folded into the signed material (never into the transmitted payload)
        // purely so a password change invalidates every previously issued cookie for free.
        byte[] signature = mac.doFinal(
                (signedPart + "|" + passwordHash).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(signature);
    }
}