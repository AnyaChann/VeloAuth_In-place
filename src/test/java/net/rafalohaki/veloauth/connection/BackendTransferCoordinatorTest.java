package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.cache.AuthCache;
import com.velocitypowered.api.proxy.ServerConnection;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import net.kyori.adventure.text.Component;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BackendTransferCoordinatorTest {

    private ConnectionManager lifecycle;
    private BackendSelector selector;
    private Player player;
    private PlayerTransferState state;
    private BackendTransferCoordinator coordinator;
    private Settings settings;

    @BeforeEach
    void setUp() {
        lifecycle = mock(ConnectionManager.class);
        selector = mock(BackendSelector.class);
        player = mock(Player.class);
        state = new PlayerTransferState(UUID.randomUUID(), player, 1L);
        settings = mock(Settings.class);
        Logger logger = mock(Logger.class);
        Messages messages = mock(Messages.class);
        coordinator = new BackendTransferCoordinator(
                lifecycle, selector, mock(AuthCache.class), settings, logger, messages);

        when(lifecycle.currentState(player)).thenReturn(state);
        when(lifecycle.isStale(state)).thenReturn(false);
        when(lifecycle.resetTasksIfCurrent(state, false)).thenReturn(true);
        when(lifecycle.scheduleOwnedTask(any(), any(), anyLong(), any(), any()))
                .thenReturn(true);
        when(selector.resolveForcedHostTarget(player, state)).thenReturn(Optional.empty());
    }

    @Test
    void transfer_NoBackendAvailable_ReturnsWaitingOutcome() {
        when(selector.findAvailableBackendServer(state)).thenReturn(Optional.empty());

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.WAITING_FOR_BACKEND, outcome);
        verify(lifecycle).scheduleOwnedTask(
                eq(state), same(state.backendWait()), eq(5L),
                eq(java.util.concurrent.TimeUnit.SECONDS), any(Runnable.class));
    }

    @Test
    void transfer_ConnectionAlreadyOwned_ReturnsCoalescedOutcome() {
        RegisteredServer backend = mock(RegisteredServer.class);
        when(backend.getServerInfo()).thenReturn(new com.velocitypowered.api.proxy.server.ServerInfo(
                "backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(selector.resolveForcedHostTarget(player, state)).thenReturn(Optional.of(backend));
        when(player.isActive()).thenReturn(true);
        state.backendConnectionActive().set(true);

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.COALESCED, outcome);
        verify(lifecycle, never()).startConnectionIfCurrent(any(), any(), any());
        verify(lifecycle, never()).finishIfCurrent(any(), anyBoolean());
    }

    @Test
    void transfer_InPlaceModeOnAuthServer_SendsUnlockAndNeverSearchesForABackend() {
        // Regression test for the bug where PostAuthFlow -> transferToBackend -> this method
        // bypassed IN_PLACE entirely and fell through to findAvailableBackendServer, which
        // always excludes the auth server itself - stranding non-premium players who go
        // through /register instead of the ServerConnectedEvent-driven auto-transfer path.
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.IN_PLACE);
        when(settings.getAuthServerInPlaceSecret()).thenReturn(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
        when(player.isActive()).thenReturn(true);
        when(player.getUniqueId()).thenReturn(state.playerId());
        when(lifecycle.isPlayerOnAuthServer(player)).thenReturn(true);
        ServerConnection connection = mock(ServerConnection.class);
        when(player.getCurrentServer()).thenReturn(Optional.of(connection));
        when(connection.sendPluginMessage(any(), any(byte[].class))).thenReturn(true);

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.CONNECTED, outcome);
        verify(selector, never()).findAvailableBackendServer(any());
        verify(connection).sendPluginMessage(any(), any(byte[].class));
    }

    @Test
    void transfer_InPlaceModeNotYetOnAuthServer_RejectsWithoutSearchingForABackend() {
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.IN_PLACE);
        when(player.isActive()).thenReturn(true);
        when(lifecycle.isPlayerOnAuthServer(player)).thenReturn(false);

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.REJECTED, outcome);
        verify(selector, never()).findAvailableBackendServer(any());
    }

    // ---- In-place unlock: ACK, timeout, bounded retry (TDS sections 8 and 11) ----

    private static final String ACK_SECRET =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    private ServerConnection inPlaceReady() {
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.IN_PLACE);
        when(settings.getAuthServerInPlaceSecret()).thenReturn(ACK_SECRET);
        when(player.isActive()).thenReturn(true);
        when(player.getUniqueId()).thenReturn(state.playerId());
        when(player.getUsername()).thenReturn("tester");
        when(lifecycle.isPlayerOnAuthServer(player)).thenReturn(true);
        ServerConnection connection = mock(ServerConnection.class);
        when(player.getCurrentServer()).thenReturn(Optional.of(connection));
        when(connection.sendPluginMessage(any(), any(byte[].class))).thenReturn(true);
        return connection;
    }

    private Runnable lastScheduledTimeout() {
        ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
        verify(lifecycle, org.mockito.Mockito.atLeastOnce()).scheduleOwnedTask(
                eq(state), same(state.unlockRetry()), anyLong(), any(), captor.capture());
        return captor.getAllValues().get(captor.getAllValues().size() - 1);
    }

    private static String nonceOfLastSend(ServerConnection connection, int expectedSends) {
        ArgumentCaptor<byte[]> payloads = ArgumentCaptor.forClass(byte[].class);
        verify(connection, times(expectedSends)).sendPluginMessage(any(), payloads.capture());
        byte[] last = payloads.getAllValues().get(payloads.getAllValues().size() - 1);
        return new String(last, StandardCharsets.UTF_8).split("\\|")[3];
    }

    private byte[] validAck(String nonce) throws Exception {
        String signed = "veloauth-ack-v1|" + state.playerId() + "|" + nonce;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HexFormat.of().parseHex(ACK_SECRET), "HmacSHA256"));
        String sig = HexFormat.of().formatHex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
        return ("v1|" + state.playerId() + "|" + nonce + "|" + sig).getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void inPlaceUnlock_SendSuccess_ArmsAnAckTimeoutInsteadOfTrustingTheSend() {
        ServerConnection connection = inPlaceReady();

        assertSame(BackendTransferOutcome.CONNECTED, coordinator.transfer(player));

        verify(connection, times(1)).sendPluginMessage(any(), any(byte[].class));
        lastScheduledTimeout();
        assertFalse(state.unlockAttempt().get().acknowledged(),
                "a successful send must not be treated as a completed unlock");
    }

    @Test
    void inPlaceUnlock_ValidAck_CompletesAndTheTimeoutDoesNothing() throws Exception {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);
        Runnable timeout = lastScheduledTimeout();
        InPlaceUnlocker.Attempt attempt = state.unlockAttempt().get();

        coordinator.handleInPlaceUnlockAck(player, validAck(nonceOfLastSend(connection, 1)));

        assertTrue(attempt.acknowledged());
        timeout.run();
        verify(connection, times(1)).sendPluginMessage(any(), any(byte[].class));
        verify(player, never()).disconnect(nullable(Component.class));
    }

    @Test
    void inPlaceUnlock_NoAck_RetriesWithFreshNoncesThenFailsClosedAfterTheLimit() {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);

        lastScheduledTimeout().run();
        lastScheduledTimeout().run();
        verify(connection, times(3)).sendPluginMessage(any(), any(byte[].class));
        verify(player, never()).disconnect(nullable(Component.class));

        lastScheduledTimeout().run();

        verify(connection, times(3)).sendPluginMessage(any(), any(byte[].class));
        verify(player).disconnect(nullable(Component.class));
    }

    @Test
    void inPlaceUnlock_AckForAnEarlierAttemptsNonce_StillCompletesTheSequence() throws Exception {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);
        String firstNonce = nonceOfLastSend(connection, 1);
        lastScheduledTimeout().run();

        coordinator.handleInPlaceUnlockAck(player, validAck(firstNonce));

        assertTrue(state.unlockAttempt().get().acknowledged());
    }

    @Test
    void inPlaceUnlock_AckWithWrongSignatureOrForeignNonce_IsIgnored() throws Exception {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);
        String nonce = nonceOfLastSend(connection, 1);

        coordinator.handleInPlaceUnlockAck(player, validAck("00".repeat(16)));
        coordinator.handleInPlaceUnlockAck(player,
                ("v1|" + state.playerId() + "|" + nonce + "|" + "00".repeat(32)).getBytes(StandardCharsets.UTF_8));

        assertFalse(state.unlockAttempt().get().acknowledged());
    }

    @Test
    void inPlaceUnlock_AckArrivingForAStaleConnection_IsIgnored() throws Exception {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);
        byte[] ack = validAck(nonceOfLastSend(connection, 1));
        InPlaceUnlocker.Attempt attempt = state.unlockAttempt().get();
        when(lifecycle.isStale(state)).thenReturn(true);

        coordinator.handleInPlaceUnlockAck(player, ack);

        assertFalse(attempt.acknowledged(), "an ACK for a superseded connection must not complete anything");
    }

    @Test
    void inPlaceUnlock_TimeoutFiringAfterTheConnectionWentStale_DoesNotRetryOrKick() {
        ServerConnection connection = inPlaceReady();
        coordinator.transfer(player);
        Runnable timeout = lastScheduledTimeout();
        when(lifecycle.isStale(state)).thenReturn(true);

        timeout.run();

        verify(connection, times(1)).sendPluginMessage(any(), any(byte[].class));
        verify(player, never()).disconnect(nullable(Component.class));
    }}
