package net.rafalohaki.veloauth.command;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionCookieCodecTest {

    private static final String SECRET_HEX =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";
    private static final String OTHER_SECRET_HEX =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    private static final String HASH = "$2a$10$abcdefghijklmnopqrstuv";
    private static final String OTHER_HASH = "$2a$10$zzzzzzzzzzzzzzzzzzzzzz";

    @Test
    void buildToken_Format_IsThreePipeSeparatedFields() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        byte[] token = SessionCookieCodec.buildToken(uuid, 24, HASH, SECRET_HEX);
        String[] parts = new String(token, StandardCharsets.UTF_8).split("\\|");

        assertEquals(3, parts.length);
        assertEquals(uuid.toString(), parts[0]);
        assertEquals(64, parts[2].length(), "HMAC-SHA256 signature must be 32 raw bytes hex-encoded");
    }

    @Test
    void verifyToken_ValidToken_ReturnsTheEncodedUuid() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();
        byte[] token = SessionCookieCodec.buildToken(uuid, 24, HASH, SECRET_HEX);

        Optional<UUID> result = SessionCookieCodec.verifyToken(token, uuid, HASH, SECRET_HEX);

        assertTrue(result.isPresent());
        assertEquals(uuid, result.get());
    }

    @Test
    void verifyToken_PasswordChangedSincIssue_Rejects() throws GeneralSecurityException {
        // The core revocation property: a password change must invalidate every cookie issued
        // before it, with no separate server-side revocation list.
        UUID uuid = UUID.randomUUID();
        byte[] token = SessionCookieCodec.buildToken(uuid, 24, HASH, SECRET_HEX);

        Optional<UUID> result = SessionCookieCodec.verifyToken(token, uuid, OTHER_HASH, SECRET_HEX);

        assertTrue(result.isEmpty());
    }

    @Test
    void verifyToken_WrongSecret_Rejects() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();
        byte[] token = SessionCookieCodec.buildToken(uuid, 24, HASH, SECRET_HEX);

        Optional<UUID> result = SessionCookieCodec.verifyToken(token, uuid, HASH, OTHER_SECRET_HEX);

        assertTrue(result.isEmpty());
    }

    @Test
    void verifyToken_UuidMismatch_Rejects() throws GeneralSecurityException {
        // Defense in depth: even a structurally/cryptographically valid cookie must not verify
        // for a UUID other than the one it was actually issued for.
        UUID issuedFor = UUID.randomUUID();
        UUID connecting = UUID.randomUUID();
        byte[] token = SessionCookieCodec.buildToken(issuedFor, 24, HASH, SECRET_HEX);

        Optional<UUID> result = SessionCookieCodec.verifyToken(token, connecting, HASH, SECRET_HEX);

        assertTrue(result.isEmpty());
    }

    @Test
    void verifyToken_Expired_Rejects() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();
        // ttlHours = 0 combined with the tiny scheduling gap between build and verify is not
        // reliable enough across CI timing, so build a token with a negative TTL directly to
        // guarantee it is already expired at verification time.
        byte[] token = SessionCookieCodec.buildToken(uuid, -1, HASH, SECRET_HEX);

        Optional<UUID> result = SessionCookieCodec.verifyToken(token, uuid, HASH, SECRET_HEX);

        assertTrue(result.isEmpty());
    }

    @Test
    void verifyToken_MalformedData_ReturnsEmptyRatherThanThrowing() {
        UUID uuid = UUID.randomUUID();

        assertTrue(SessionCookieCodec.verifyToken(
                "not-a-valid-cookie".getBytes(StandardCharsets.UTF_8), uuid, HASH, SECRET_HEX).isEmpty());
        assertTrue(SessionCookieCodec.verifyToken(
                new byte[0], uuid, HASH, SECRET_HEX).isEmpty());
    }

    @Test
    void buildToken_MalformedSecretHex_ThrowsRatherThanSigningWithGarbage() {
        UUID uuid = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> SessionCookieCodec.buildToken(uuid, 24, HASH, "not-hex"));
    }
}