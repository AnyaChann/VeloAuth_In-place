package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.event.EventManager;
import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.api.proxy.server.ServerPing;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.api.event.PlayerAuthenticatedEvent;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PlayerAuthenticatedEvent: who announces, how often, with which method, and what can never go wrong
 * (an authentication must not depend on, or be broken by, whoever listens to the event).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PlayerAuthenticatedAnnouncementTest {

    @Mock
    private ProxyServer proxyServer;

    @Mock
    private Logger logger;

    @Mock
    private AuthCache authCache;

    @Mock
    private Settings settings;

    @Mock
    private EventManager eventManager;

    private final List<PlayerAuthenticatedEvent> fired = new ArrayList<>();
    private ConnectionManager connectionManager;

    @BeforeEach
    void setUp() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);
        when(settings.getAuthServerName()).thenReturn("auth");
        when(settings.getConnectionTimeoutSeconds()).thenReturn(1);
        when(settings.getPingTimeoutMillis()).thenReturn(2000);
        when(settings.getAutoTransferDelayMillis()).thenReturn(1500);
        when(proxyServer.getEventManager()).thenReturn(eventManager);
        doAnswer(invocation -> {
            fired.add((PlayerAuthenticatedEvent) invocation.getArgument(0));
            return null;
        }).when(eventManager).fireAndForget(any());

        Metrics.Factory metricsFactory = mock(Metrics.Factory.class);
        VeloAuth plugin = new VeloAuth(proxyServer, logger, Path.of("."), metricsFactory);
        connectionManager = new ConnectionManager(plugin, authCache, settings, messages);
    }

    private static Player player(UUID id, String name, boolean online) {
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(id);
        when(player.getUsername()).thenReturn(name);
        when(player.isOnlineMode()).thenReturn(online);
        when(player.isActive()).thenReturn(true);
        return player;
    }

    private PlayerAuthenticatedEvent onlyEvent() {
        assertEquals(1, fired.size(), "exactly one event expected, got " + fired);
        return fired.get(0);
    }

    // ---- which server ----

    @Test
    void announce_withAServerName_carriesItInTheEvent() {
        Player player = player(UUID.randomUUID(), "OnSurvival", false);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player, "survival");

        assertEquals("survival", onlyEvent().getServerName());
    }

    @Test
    void announce_withoutAServerName_reportsAnEmptyOne() {
        Player player = player(UUID.randomUUID(), "NoServer", false);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player);

        assertEquals("", onlyEvent().getServerName());
    }

    // ---- method and premium flag ----

    @Test
    void announce_noRecordedMethod_offlinePlayer_isASessionResume() {
        Player player = player(UUID.randomUUID(), "Resumed", false);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player);

        PlayerAuthenticatedEvent event = onlyEvent();
        assertSame(player, event.getPlayer());
        assertEquals(PlayerAuthenticatedEvent.METHOD_SESSION, event.getMethod());
        assertFalse(event.isPremium());
    }

    @Test
    void announce_noRecordedMethod_onlineModePlayer_isPremium() {
        Player player = player(UUID.randomUUID(), "Premium", true);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player);

        PlayerAuthenticatedEvent event = onlyEvent();
        assertEquals(PlayerAuthenticatedEvent.METHOD_PREMIUM, event.getMethod());
        assertTrue(event.isPremium());
    }

    @Test
    void announce_recordedMethod_isReportedAsIs() {
        for (String method : List.of(PlayerAuthenticatedEvent.METHOD_LOGIN,
                PlayerAuthenticatedEvent.METHOD_REGISTER, PlayerAuthenticatedEvent.METHOD_TOTP)) {
            fired.clear();
            Player player = player(UUID.randomUUID(), "Typed" + method, false);
            connectionManager.beginTransferSession(player);
            connectionManager.recordAuthMethod(player, method);

            connectionManager.announceAuthenticated(player);

            assertEquals(method, onlyEvent().getMethod());
            assertFalse(onlyEvent().isPremium(), "typing a password is never a premium authentication");
        }
    }

    @Test
    void announce_recordedMethodOnAnOnlineModePlayer_keepsTheMethodAndTheFlag() {
        Player player = player(UUID.randomUUID(), "PremiumWithPassword", true);
        connectionManager.beginTransferSession(player);
        connectionManager.recordAuthMethod(player, PlayerAuthenticatedEvent.METHOD_LOGIN);

        connectionManager.announceAuthenticated(player);

        PlayerAuthenticatedEvent event = onlyEvent();
        assertEquals(PlayerAuthenticatedEvent.METHOD_LOGIN, event.getMethod());
        assertTrue(event.isPremium());
    }

    // ---- once per connection, and only for the current connection ----

    @Test
    void announce_calledTwice_firesOnce() {
        Player player = player(UUID.randomUUID(), "Twice", false);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player);
        connectionManager.announceAuthenticated(player);

        onlyEvent();
    }

    @Test
    void announce_afterSwitchingServers_doesNotFireAgain() {
        Player player = player(UUID.randomUUID(), "Switcher", false);
        connectionManager.beginTransferSession(player);

        connectionManager.announceAuthenticated(player); // first backend
        connectionManager.announceAuthenticated(player); // ServerConnected for the second backend

        onlyEvent();
    }

    @Test
    void announce_aNewConnectionOfTheSamePlayer_announcesAgain() {
        UUID id = UUID.randomUUID();
        Player first = player(id, "Rejoiner", false);
        connectionManager.beginTransferSession(first);
        connectionManager.announceAuthenticated(first);

        Player second = player(id, "Rejoiner", false);
        connectionManager.beginTransferSession(second);
        connectionManager.announceAuthenticated(second);

        assertEquals(2, fired.size());
        assertSame(second, fired.get(1).getPlayer());
    }

    @Test
    void announce_withoutAConnectionState_doesNothing() {
        connectionManager.announceAuthenticated(player(UUID.randomUUID(), "Unknown", false));

        assertTrue(fired.isEmpty());
    }

    @Test
    void announce_afterTheConnectionWasCleared_doesNothing() {
        Player player = player(UUID.randomUUID(), "Gone", false);
        connectionManager.beginTransferSession(player);
        connectionManager.clearTransferState(player);

        connectionManager.announceAuthenticated(player);

        assertTrue(fired.isEmpty());
    }

    @Test
    void announce_forASupersededConnection_doesNothing() {
        UUID id = UUID.randomUUID();
        Player old = player(id, "Old", false);
        Player current = player(id, "Current", false);
        connectionManager.beginTransferSession(old);
        connectionManager.beginTransferSession(current);

        connectionManager.announceAuthenticated(old);

        assertTrue(fired.isEmpty(), "a retired connection must never announce");
    }

    @Test
    void recordAuthMethod_forASupersededConnection_doesNotLeakIntoTheCurrentOne() {
        UUID id = UUID.randomUUID();
        Player old = player(id, "Old", false);
        Player current = player(id, "Current", false);
        connectionManager.beginTransferSession(old);
        connectionManager.beginTransferSession(current);

        connectionManager.recordAuthMethod(old, PlayerAuthenticatedEvent.METHOD_LOGIN);
        connectionManager.announceAuthenticated(current);

        assertEquals(PlayerAuthenticatedEvent.METHOD_SESSION, onlyEvent().getMethod());
    }

    @Test
    void recordAuthMethod_withoutAConnectionState_doesNotThrow() {
        assertDoesNotThrow(() -> connectionManager.recordAuthMethod(
                player(UUID.randomUUID(), "Unknown", false), PlayerAuthenticatedEvent.METHOD_LOGIN));
    }

    // ---- listeners can never break authentication ----

    @Test
    void announce_whenTheEventManagerFails_neverPropagates() {
        Player player = player(UUID.randomUUID(), "Fragile", false);
        connectionManager.beginTransferSession(player);
        doThrow(new IllegalStateException("event bus down")).when(eventManager).fireAndForget(any());

        assertDoesNotThrow(() -> connectionManager.announceAuthenticated(player));
        assertDoesNotThrow(() -> connectionManager.announceAuthenticated(player));
    }

    @Test
    void announce_whenThePlayerObjectMisbehaves_neverPropagates() {
        Player player = player(UUID.randomUUID(), "Broken", false);
        connectionManager.beginTransferSession(player);
        when(player.isOnlineMode()).thenThrow(new IllegalStateException("connection closed"));

        assertDoesNotThrow(() -> connectionManager.announceAuthenticated(player));
        assertTrue(fired.isEmpty());
    }

    // ---- limbo mode: a successful backend transfer retires the state; both event orders give one event ----

    private void prepareSuccessfulBackendTransfer(Player player) {
        RegisteredServer backend = mock(RegisteredServer.class);
        ConnectionRequestBuilder builder = mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result result = mock(ConnectionRequestBuilder.Result.class);
        when(backend.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backend.ping()).thenReturn(CompletableFuture.completedFuture(mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backend));
        when(player.createConnectionRequest(backend)).thenReturn(builder);
        when(builder.connect()).thenReturn(CompletableFuture.completedFuture(result));
        when(result.isSuccessful()).thenReturn(true);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");
    }

    @Test
    void successfulTransfer_thenServerConnected_firesExactlyOnceWithTheTypedMethod() {
        Player player = player(UUID.randomUUID(), "LimboLogin", false);
        prepareSuccessfulBackendTransfer(player);
        connectionManager.recordAuthMethod(player, PlayerAuthenticatedEvent.METHOD_LOGIN);

        assertTrue(connectionManager.transferToBackend(player));
        // ServerConnectedEvent handled after the state was retired: nothing left to announce from there
        connectionManager.announceAuthenticated(player);

        assertEquals(PlayerAuthenticatedEvent.METHOD_LOGIN, onlyEvent().getMethod());
    }

    @Test
    void serverConnected_thenSuccessfulTransfer_firesExactlyOnce() {
        Player player = player(UUID.randomUUID(), "LimboRegister", false);
        prepareSuccessfulBackendTransfer(player);
        connectionManager.recordAuthMethod(player, PlayerAuthenticatedEvent.METHOD_REGISTER);

        connectionManager.announceAuthenticated(player); // ServerConnectedEvent first, state still current
        assertTrue(connectionManager.transferToBackend(player));

        assertEquals(PlayerAuthenticatedEvent.METHOD_REGISTER, onlyEvent().getMethod());
    }

    @Test
    void failedTransfer_doesNotAnnounce() {
        Player player = player(UUID.randomUUID(), "NoBackend", false);
        RegisteredServer backend = mock(RegisteredServer.class);
        ConnectionRequestBuilder builder = mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result result = mock(ConnectionRequestBuilder.Result.class);
        when(backend.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backend.ping()).thenReturn(CompletableFuture.completedFuture(mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backend));
        when(player.createConnectionRequest(backend)).thenReturn(builder);
        when(builder.connect()).thenReturn(CompletableFuture.completedFuture(result));
        when(result.isSuccessful()).thenReturn(false);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        connectionManager.transferToBackend(player);

        assertTrue(fired.isEmpty(), "a refused connection request means the player is NOT playing yet");
    }

    // ---- in-place mode: the moment is the backend's signed ACK ----

    private BackendTransferCoordinator replaceCoordinatorWithMock() throws Exception {
        BackendTransferCoordinator coordinator = mock(BackendTransferCoordinator.class);
        Field field = ConnectionManager.class.getDeclaredField("backendTransferCoordinator");
        field.setAccessible(true);
        field.set(connectionManager, coordinator);
        return coordinator;
    }

    @Test
    void inPlaceAck_accepted_announcesOnce() throws Exception {
        BackendTransferCoordinator coordinator = replaceCoordinatorWithMock();
        Player player = player(UUID.randomUUID(), "InPlace", false);
        connectionManager.beginTransferSession(player);
        connectionManager.recordAuthMethod(player, PlayerAuthenticatedEvent.METHOD_LOGIN);
        byte[] ack = {1, 2, 3};
        when(coordinator.handleInPlaceUnlockAck(player, ack)).thenReturn(true);

        connectionManager.handleInPlaceUnlockAck(player, ack);
        connectionManager.handleInPlaceUnlockAck(player, ack);

        assertEquals(PlayerAuthenticatedEvent.METHOD_LOGIN, onlyEvent().getMethod());
    }

    @Test
    void inPlaceAck_rejected_doesNotAnnounce() throws Exception {
        BackendTransferCoordinator coordinator = replaceCoordinatorWithMock();
        Player player = player(UUID.randomUUID(), "InPlaceForged", false);
        connectionManager.beginTransferSession(player);
        byte[] ack = {9, 9, 9};
        when(coordinator.handleInPlaceUnlockAck(player, ack)).thenReturn(false);

        connectionManager.handleInPlaceUnlockAck(player, ack);

        assertTrue(fired.isEmpty(), "an ignored or forged ACK must not announce an authentication");
    }
}
