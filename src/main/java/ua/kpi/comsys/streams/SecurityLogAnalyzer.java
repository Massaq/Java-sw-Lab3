package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Gatherer;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    private static final String CRITICAL_LEVEL = "CRITICAL";

    // Знайти першу критичну подію в нескінченному потоці логів
    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }

        return stream
                .filter(Objects::nonNull)
                .filter(log -> Optional.ofNullable(log.severityLevel())
                        .map(CRITICAL_LEVEL::equals)
                        .orElse(false))
                .findFirst();
    }

    // Фільтрувати логи за часовим вікном у нескінченному потоці
    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        if (stream == null || deadline == null) {
            throw new IllegalArgumentException("Stream and deadline cannot be null");
        }

        return stream
                .filter(Objects::nonNull)
                .takeWhile(log -> Optional.ofNullable(log.timestamp())
                        .map(ts -> ts.isBefore(deadline))
                        .orElse(false))
                .toList();
    }

    // Кастомний Gatherer для детекції атак типу "Burst"
    // (якщо від однієї IP надходить >= burstThreshold подій поспіль без інших IP)
    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        if (stream == null) {
            throw new IllegalArgumentException("Stream cannot be null");
        }
        if (burstThreshold <= 0 || maxIpsToReport <= 0) {
            throw new IllegalArgumentException("burstThreshold and maxIpsToReport must be strictly positive (> 0)");
        }

        class BurstState {
            String currentIp = null;
            int consecutiveCount = 0;
            int reportedCount = 0;
            boolean currentBurstReported = false;
        }

        Gatherer<SecurityLog, BurstState, String> burstGatherer = Gatherer.ofSequential(
                BurstState::new,
                Gatherer.Integrator.of((state, log, downstream) -> {
                    if (state.reportedCount >= maxIpsToReport || downstream.isRejecting()) {
                        return false;
                    }
                    if (log == null || log.ipAddress() == null) {
                        return true;
                    }

                    String ip = log.ipAddress();
                    if (ip.equals(state.currentIp)) {
                        state.consecutiveCount++;
                    } else {
                        state.currentIp = ip;
                        state.consecutiveCount = 1;
                        state.currentBurstReported = false;
                    }

                    if (state.consecutiveCount >= burstThreshold && !state.currentBurstReported) {
                        state.currentBurstReported = true;
                        state.reportedCount++;
                        boolean canContinue = downstream.push(ip);
                        if (!canContinue || state.reportedCount >= maxIpsToReport) {
                            return false;
                        }
                    }

                    return true;
                })
        );

        return stream.gather(burstGatherer).toList();
    }
}
