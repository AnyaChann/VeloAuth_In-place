package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ServerConnection;
import net.rafalohaki.veloauth.config.Settings;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InPlaceUnlockerTest {

    private static final String SECRET_HEX =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";
    private static final String OTHER_SECRET_HEX =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    @Test
    void buildSignedUnlock_Format_IsVersionedFiveFieldsWithMatchingUuid() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        var signed = InPlaceUnlocker.buildSignedUnlock(uuid, SECRET_HEX);
        String[] parts = new String(signed.payload(), StandardCharsets.UTF_8).split("\\|");

        assertEquals(5, parts.length);
        assertEquals("v1", parts[0]);
        assertEquals(uuid.toString(), parts[1]);
        assertEquals(32, parts[3].length(), "nonce must be 16 raw bytes hex-encoded");
        assertEquals(signed.nonceHex(), parts[3], "the returned nonce is the one inside the payload");
        assertEquals(64, parts[4].length(), "HMAC-SHA256 signature must be 32 raw bytes hex-encoded");
    }

    @Test
    void buildSignedUnlock_Signature_CoversLabelAndAllFields() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        var signed = InPlaceUnlocker.buildSignedUnlock(uuid, SECRET_HEX);
        String[] parts = new String(signed.payload(), StandardCharsets.UTF_8).split("\\|");
        String signedPart = "veloauth-unlock-v1|" + parts[1] + "|" + parts[2] + "|" + parts[3];

        assertEquals(independentHmacHex(SECRET_HEX, signedPart), parts[4]);
        assertNotEquals(independentHmacHex(SECRET_HEX, parts[1] + "|" + parts[2] + "|" + parts[3]), parts[4],
                "the direction label must be part of the signed input (domain separation)");
    }

    @Test
    void buildSignedUnlock_WrongSecret_ProducesADifferentSignature() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        var signed = InPlaceUnlocker.buildSignedUnlock(uuid, SECRET_HEX);
        String[] parts = new String(signed.payload(), StandardCharsets.UTF_8).split("\\|");
        String signedPart = "veloauth-unlock-v1|" + parts[1] + "|" + parts[2] + "|" + parts[3];

        assertNotEquals(independentHmacHex(OTHER_SECRET_HEX, signedPart), parts[4],
                "a forged payload signed with a different key must not verify");
    }

    @Test
    void buildSignedUnlock_TwoCallsForSamePlayer_ProduceDifferentNoncesAndSignatures()
            throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        var first = InPlaceUnlocker.buildSignedUnlock(uuid, SECRET_HEX);
        var second = InPlaceUnlocker.buildSignedUnlock(uuid, SECRET_HEX);

        assertNotEquals(first.nonceHex(), second.nonceHex(),
                "each attempt must carry a fresh nonce so a captured payload cannot be replayed verbatim");
        assertNotEquals(new String(first.payload(), StandardCharsets.UTF_8),
                new String(second.payload(), StandardCharsets.UTF_8));
    }

    @Test
    void buildSignedUnlock_MalformedSecretHex_ThrowsRatherThanSendingUnsigned() {
        UUID uuid = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> InPlaceUnlocker.buildSignedUnlock(uuid, "not-hex"));
    }

    @Test
    void unlock_NoCurrentServer_ReturnsFalseWithoutThrowing() {
        Logger logger = mock(Logger.class);
        Settings settings = mock(Settings.class);
        Player player = mock(Player.class);
        when(player.getCurrentServer()).thenReturn(Optional.empty());
        when(player.getUsername()).thenReturn("test-player");

        InPlaceUnlocker unlocker = new InPlaceUnlocker(logger, settings);

        assertFalse(unlocker.unlock(player, new InPlaceUnlocker.Attempt()));
    }

    @Test
    void unlock_WithCurrentServer_SendsAVerifiablePayloadAndRegistersItsNonce()
            throws GeneralSecurityException {
        Logger logger = mock(Logger.class);
        Settings settings = mock(Settings.class);
        when(settings.getAuthServerInPlaceSecret()).thenReturn(SECRET_HEX);

        UUID uuid = UUID.randomUUID();
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(uuid);
        when(player.getUsername()).thenReturn("test-player");
        ServerConnection connection = mock(ServerConnection.class);
        when(player.getCurrentServer()).thenReturn(Optional.of(connection));
        when(connection.sendPluginMessage(eq(InPlaceUnlocker.CHANNEL), any(byte[].class))).thenReturn(true);

        InPlaceUnlocker unlocker = new InPlaceUnlocker(logger, settings);
        InPlaceUnlocker.Attempt attempt = new InPlaceUnlocker.Attempt();
        assertTrue(unlocker.unlock(player, attempt));

        var captor = org.mockito.ArgumentCaptor.forClass(byte[].class);
        verify(connection).sendPluginMessage(eq(InPlaceUnlocker.CHANNEL), captor.capture());
        String[] parts = new String(captor.getValue(), StandardCharsets.UTF_8).split("\\|");
        assertEquals("v1", parts[0]);
        assertEquals(uuid.toString(), parts[1]);
        assertEquals(independentHmacHex(SECRET_HEX,
                "veloauth-unlock-v1|" + parts[1] + "|" + parts[2] + "|" + parts[3]), parts[4]);
        assertTrue(attempt.ownsNonce(parts[3]), "the attempt must remember the nonce it issued");
    }

    // ---- ACK verification ----

    private record AckFixture(InPlaceUnlocker unlocker, Player player, InPlaceUnlocker.Attempt attempt,
                              UUID uuid, String nonce) {
    }

    private static AckFixture ackFixture() throws GeneralSecurityException {
        Settings settings = mock(Settings.class);
        when(settings.getAuthServerInPlaceSecret()).thenReturn(SECRET_HEX);
        UUID uuid = UUID.randomUUID();
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(uuid);
        when(player.getUsername()).thenReturn("test-player");
        ServerConnection connection = mock(ServerConnection.class);
        when(player.getCurrentServer()).thenReturn(Optional.of(connection));
        when(connection.sendPluginMessage(eq(InPlaceUnlocker.CHANNEL), any(byte[].class))).thenReturn(true);

        InPlaceUnlocker unlocker = new InPlaceUnlocker(mock(Logger.class), settings);
        InPlaceUnlocker.Attempt attempt = new InPlaceUnlocker.Attempt();
        unlocker.unlock(player, attempt);
        var captor = org.mockito.ArgumentCaptor.forClass(byte[].class);
        verify(connection).sendPluginMessage(eq(InPlaceUnlocker.CHANNEL), captor.capture());
        String nonce = new String(captor.getValue(), StandardCharsets.UTF_8).split("\\|")[3];
        return new AckFixture(unlocker, player, attempt, uuid, nonce);
    }

    private static byte[] ack(String secretHex, UUID uuid, String nonce) throws GeneralSecurityException {
        String sig = independentHmacHex(secretHex, "veloauth-ack-v1|" + uuid + "|" + nonce);
        return ("v1|" + uuid + "|" + nonce + "|" + sig).getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void acknowledge_ValidAckForIssuedNonce_IsAccepted() throws GeneralSecurityException {
        AckFixture f = ackFixture();

        assertTrue(f.unlocker().acknowledge(f.player(), f.attempt(), ack(SECRET_HEX, f.uuid(), f.nonce())));
    }

    @Test
    void acknowledge_WrongSecret_IsRejected() throws GeneralSecurityException {
        AckFixture f = ackFixture();

        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(),
                ack(OTHER_SECRET_HEX, f.uuid(), f.nonce())));
    }

    @Test
    void acknowledge_NonceNeverIssuedByThisAttempt_IsRejected() throws GeneralSecurityException {
        AckFixture f = ackFixture();

        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(),
                ack(SECRET_HEX, f.uuid(), "00".repeat(16))));
    }

    @Test
    void acknowledge_AckForAnotherPlayersUuid_IsRejected() throws GeneralSecurityException {
        AckFixture f = ackFixture();

        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(),
                ack(SECRET_HEX, UUID.randomUUID(), f.nonce())));
    }

    @Test
    void acknowledge_UnlockMessageReplayedAsAck_IsRejected() throws GeneralSecurityException {
        AckFixture f = ackFixture();
        // Signed with the UNLOCK label over the same fields: must not pass as an ACK.
        String sig = independentHmacHex(SECRET_HEX, "veloauth-unlock-v1|" + f.uuid() + "|" + f.nonce());
        byte[] forged = ("v1|" + f.uuid() + "|" + f.nonce() + "|" + sig).getBytes(StandardCharsets.UTF_8);

        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(), forged));
    }

    @Test
    void acknowledge_MalformedOrOversized_IsRejectedWithoutThrowing() throws GeneralSecurityException {
        AckFixture f = ackFixture();

        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(), null));
        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(), "garbage".getBytes(StandardCharsets.UTF_8)));
        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(),
                ("v2|" + f.uuid() + "|" + f.nonce() + "|00").getBytes(StandardCharsets.UTF_8)));
        assertFalse(f.unlocker().acknowledge(f.player(), f.attempt(), new byte[InPlaceUnlocker.MAX_ACK_BYTES + 1]));
    }

    @Test
    void attempt_ZeroDeadline_IsImmediatelyExpired() {
        InPlaceUnlocker.Attempt attempt = new InPlaceUnlocker.Attempt(0);

        assertTrue(attempt.expired());
        assertEquals(0, attempt.remainingMillis());
    }

    @Test
    void attempt_MarkAcknowledged_IsTrueOnlyTheFirstTime() {
        InPlaceUnlocker.Attempt attempt = new InPlaceUnlocker.Attempt();

        assertTrue(attempt.markAcknowledged());
        assertFalse(attempt.markAcknowledged());
        assertTrue(attempt.acknowledged());
    }

    private static String independentHmacHex(String secretHex, String data) throws GeneralSecurityException {
        byte[] key = HexFormat.of().parseHex(secretHex);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }
}
