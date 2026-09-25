package homes.milky.vpn

import homes.milky.vpn.vpn.ConnectionAttemptGate
import homes.milky.vpn.vpn.parseStoredActiveProfile
import org.junit.Assert.*
import org.junit.Test

class ConnectionAttemptGateTest {
    @Test fun lateCoreSuccessCannotPublishAfterCancellation() {
        val gate = ConnectionAttemptGate()
        val a = gate.begin()
        val stop = gate.cancelCurrent()
        var published = false
        assertFalse(gate.runIfActive(a) { published = true })
        assertFalse(published)
        assertTrue(gate.runIfGeneration(stop) {})
    }

    @Test fun olderDisconnectAndShutdownCannotTerminateNextAttempt() {
        val gate = ConnectionAttemptGate()
        val a = gate.begin()
        val stop = gate.cancelCurrent()
        val b = gate.begin()
        assertFalse(gate.finishIfActive(a) { fail("stale shutdown") })
        assertFalse(gate.runIfGeneration(stop) { fail("stale disconnect") })
        assertTrue(gate.runIfActive(b) {})
    }

    @Test fun coreFailureCanOnlyFinishCurrentAttemptOnce() {
        val gate = ConnectionAttemptGate()
        val a = gate.begin()
        assertTrue(gate.finishIfActive(a) {})
        assertFalse(gate.finishIfActive(a) { fail("duplicate terminal event") })
        assertFalse(gate.runIfActive(a) { fail("success after failure") })
    }

    @Test fun staleNetworkCallbacksCannotMutateOrScheduleWhileCurrentCan() {
        val gate = ConnectionAttemptGate()
        val oldAttempt = gate.begin()
        gate.cancelCurrent()
        val currentAttempt = gate.begin()
        var underlyingNetworkUpdates = 0
        var reverificationsScheduled = 0

        assertFalse(gate.runIfActive(oldAttempt) {
            underlyingNetworkUpdates += 1
            reverificationsScheduled += 1
        })
        assertEquals(0, underlyingNetworkUpdates)
        assertEquals(0, reverificationsScheduled)

        assertTrue(gate.runIfActive(currentAttempt) {
            underlyingNetworkUpdates += 1
            reverificationsScheduled += 1
        })
        assertEquals(1, underlyingNetworkUpdates)
        assertEquals(1, reverificationsScheduled)
    }

    @Test fun malformedSealedProfileBecomesSanitizedConfigError() {
        try {
            parseStoredActiveProfile("{bad-secret-json")
            fail("should reject corrupt JSON")
        } catch (error: IllegalArgumentException) {
            assertEquals("active profile invalid", error.message)
        }
    }
}
