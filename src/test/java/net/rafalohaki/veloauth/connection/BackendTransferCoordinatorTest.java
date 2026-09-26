package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.cache.AuthCache;
import com.velocitypowered.api.proxy.ServerConnection;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
}
