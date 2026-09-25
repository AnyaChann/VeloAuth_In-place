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
    void buildSignedPayload_Format_IsFourPipeSeparatedFieldsWithMatchingUuid() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        byte[] payload = InPlaceUnlocker.buildSignedPayload(uuid, SECRET_HEX);
        String body = new String(payload, StandardCharsets.UTF_8);
        String[] parts = body.split("\\|");

        assertEquals(4, parts.length);
        assertEquals(uuid.toString(), parts[0]);
        assertEquals(32, parts[2].length(), "nonce must be 16 raw bytes hex-encoded");
        assertEquals(64, parts[3].length(), "HMAC-SHA256 signature must be 32 raw bytes hex-encoded");
    }

    @Test
    void buildSignedPayload_Signature_VerifiesAgainstIndependentHmacComputation() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        byte[] payload = InPlaceUnlocker.buildSignedPayload(uuid, SECRET_HEX);
        String body = new String(payload, StandardCharsets.UTF_8);
        String[] parts = body.split("\\|");
        String signedPart = parts[0] + "|" + parts[1] + "|" + parts[2];

        String expectedSignature = independentHmacHex(SECRET_HEX, signedPart);
        assertEquals(expectedSignature, parts[3]);
    }

    @Test
    void buildSignedPayload_WrongSecret_ProducesADifferentSignature() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        byte[] payload = InPlaceUnlocker.buildSignedPayload(uuid, SECRET_HEX);
        String body = new String(payload, StandardCharsets.UTF_8);
        String[] parts = body.split("\\|");
        String signedPart = parts[0] + "|" + parts[1] + "|" + parts[2];

        String signatureWithOtherSecret = independentHmacHex(OTHER_SECRET_HEX, signedPart);
        assertNotEquals(signatureWithOtherSecret, parts[3],
                "a forged payload signed with a different key must not verify");
    }

    @Test
    void buildSignedPayload_TwoCallsForSamePlayer_ProduceDifferentNoncesAndSignatures() throws GeneralSecurityException {
        UUID uuid = UUID.randomUUID();

        String first = new String(InPlaceUnlocker.buildSignedPayload(uuid, SECRET_HEX), StandardCharsets.UTF_8);
        String second = new String(InPlaceUnlocker.buildSignedPayload(uuid, SECRET_HEX), StandardCharsets.UTF_8);

        assertNotEquals(first, second,
                "each unlock must carry a fresh nonce so a captured payload cannot be replayed verbatim");
    }

    @Test
    void buildSignedPayload_MalformedSecretHex_ThrowsRatherThanSendingUnsigned() {
        UUID uuid = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> InPlaceUnlocker.buildSignedPayload(uuid, "not-hex"));
    }

    @Test
    void unlock_NoCurrentServer_ReturnsFalseWithoutThrowing() {
        Logger logger = mock(Logger.class);
        Settings settings = mock(Settings.class);
        Player player = mock(Player.class);
        when(player.getCurrentServer()).thenReturn(Optional.empty());
        when(player.getUsername()).thenReturn("test-player");

        InPlaceUnlocker unlocker = new InPlaceUnlocker(logger, settings);

        assertFalse(unlocker.unlock(player));
    }

    @Test
    void unlock_WithCurrentServer_SendsAPayloadThatVerifiesAgainstTheConfiguredSecret()
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
        assertTrue(unlocker.unlock(player));

        var captor = org.mockito.ArgumentCaptor.forClass(byte[].class);
        verify(connection).sendPluginMessage(eq(InPlaceUnlocker.CHANNEL), captor.capture());
        String body = new String(captor.getValue(), StandardCharsets.UTF_8);
        String[] parts = body.split("\\|");
        assertEquals(uuid.toString(), parts[0]);
        assertEquals(independentHmacHex(SECRET_HEX, parts[0] + "|" + parts[1] + "|" + parts[2]), parts[3]);
    }

    private static String independentHmacHex(String secretHex, String data) throws GeneralSecurityException {
        byte[] key = HexFormat.of().parseHex(secretHex);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }
}