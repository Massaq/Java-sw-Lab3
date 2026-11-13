package ua.kpi.comsys.streams;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLogAnalyzerTest {

    private SecurityLogAnalyzer analyzer;
    private LocalDateTime baseTime;

    @BeforeEach
    void setUp() {
        analyzer = new SecurityLogAnalyzer();
        baseTime = LocalDateTime.of(2026, 11, 13, 12, 0, 0);
    }

    @Test
    @Timeout(2)
    void findFirstCriticalEvent_ShouldFindOnInfiniteStream() {
        Stream<SecurityLog> infiniteLogs = Stream.iterate(1, i -> i + 1)
                .map(i -> new SecurityLog(
                        "192.168.1." + (i % 255),
                        i == 500 ? "CRITICAL" : "INFO",
                        "Event #" + i,
                        baseTime.plusSeconds(i)
                ));

        Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(infiniteLogs);

        assertTrue(result.isPresent());
        assertEquals("CRITICAL", result.get().severityLevel());
        assertEquals("Event #500", result.get().eventDescription());
    }

    @Test
    void findFirstCriticalEvent_ShouldReturnEmptyWhenNoCriticalEventsInFiniteStream() {
        Stream<SecurityLog> finiteLogs = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "Login", baseTime),
                new SecurityLog("10.0.0.2", "WARN", "Retry", baseTime.plusSeconds(5))
        );

        Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(finiteLogs);

        assertTrue(result.isEmpty());
    }

    @Test
    void findFirstCriticalEvent_ShouldThrowExceptionWhenStreamIsNull() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.findFirstCriticalEvent(null));
    }

    @Test
    @Timeout(2)
    void getLogsBeforeDeadline_ShouldStopAtDeadlineOnInfiniteStream() {
        LocalDateTime deadline = baseTime.plusMinutes(5);

        Stream<SecurityLog> infiniteLogs = Stream.iterate(0, i -> i + 1)
                .map(i -> new SecurityLog(
                        "10.0.0.1",
                        "INFO",
                        "Heartbeat",
                        baseTime.plusMinutes(i)
                ));

        List<SecurityLog> logs = analyzer.getLogsBeforeDeadline(infiniteLogs, deadline);

        assertEquals(5, logs.size());
        assertTrue(logs.stream().allMatch(log -> log.timestamp().isBefore(deadline)));
    }

    @Test
    void getLogsBeforeDeadline_ShouldThrowExceptionOnNullArguments() {
        Stream<SecurityLog> emptyStream = Stream.empty();
        assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(null, baseTime));
        assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(emptyStream, null));
    }

    @Test
    @Timeout(2)
    void detectIpBursts_ShouldDetectBurstsAndTerminateOnInfiniteStream() {
        AtomicInteger counter = new AtomicInteger(0);

        Stream<SecurityLog> infiniteLogs = Stream.generate(() -> {
            int idx = counter.getAndIncrement();
            int group = idx / 10;
            String ip = "172.16.0." + (group + 1);
            return new SecurityLog(ip, "WARN", "Port scan", baseTime.plusSeconds(idx));
        });

        List<String> detectedIps = analyzer.detectIpBursts(infiniteLogs, 4, 3);

        assertEquals(List.of("172.16.0.1", "172.16.0.2", "172.16.0.3"), detectedIps);
    }

    @Test
    void detectIpBursts_ShouldIgnoreInterruptedSeriesAndDetectOnlyContinuousBursts() {
        Stream<SecurityLog> logs = Stream.of(
                new SecurityLog("10.0.0.1", "INFO", "Req", baseTime),
                new SecurityLog("10.0.0.1", "INFO", "Req", baseTime.plusSeconds(1)),
                new SecurityLog("10.0.0.2", "INFO", "Interrupt", baseTime.plusSeconds(2)),
                new SecurityLog("10.0.0.1", "INFO", "Req", baseTime.plusSeconds(3)),
                new SecurityLog("10.0.0.3", "WARN", "Burst 1", baseTime.plusSeconds(4)),
                new SecurityLog("10.0.0.3", "WARN", "Burst 2", baseTime.plusSeconds(5)),
                new SecurityLog("10.0.0.3", "WARN", "Burst 3", baseTime.plusSeconds(6)),
                new SecurityLog("10.0.0.3", "WARN", "Burst 4", baseTime.plusSeconds(7))
        );

        List<String> detected = analyzer.detectIpBursts(logs, 3, 5);

        assertEquals(List.of("10.0.0.3"), detected);
    }

    @Test
    void detectIpBursts_ShouldThrowExceptionOnInvalidArguments() {
        Stream<SecurityLog> stream = Stream.empty();
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(null, 3, 2));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(stream, 0, 2));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(stream, -1, 2));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(stream, 3, 0));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(stream, 3, -5));
    }
}
