# ADR-025: Calendar and Time-of-Day Bandwidth Scheduler

Status: Accepted · Date: 2026-10-14

## Problem

Enterprise datacenters, media production studios, and multi-tenant cloud environments operate under varying network capacity, business hours, and ISP peering costs:
1. **Business-Hours Contention**: Uncapped bulk data synchronization during peak business hours saturates WAN links, starving interactive office traffic, VoIP streams, and transactional database replication.
2. **Off-Peak Underutilization**: Capping transfers to a static, conservative rate limit (e.g. 50 Mbps) prevents organizations from exploiting unmetered off-peak or weekend multi-gigabit throughput.
3. **Connection Restarts & Fragile Cron Scripts**: Operators historically relied on external cron jobs to kill and restart transfer daemons or mutate firewall/traffic-control rules (`tc-tbf`), aborting in-flight transfers, dropping QUIC sessions, and requiring root/sudo privileges.
4. **Timezone & Daylight Ambiguity**: Datacenters spread across UTC offsets require accurate local civil time evaluation without dragging in heavy, external C or timezone dependencies that could violate `#![forbid(unsafe_code)]`.

## Options Considered

1. **External Cron Scripts with Process Restarts**:
   - Schedule cron jobs that kill running transfer tasks and relaunch with altered `--rate-limit` parameters.
   - *Rejected*: Drops active QUIC transport connections, triggers re-handshakes, risks partial transfer corruption, and requires external process supervision.
2. **Linux Traffic Control (`tc` / `iptables`)**:
   - Manage traffic control queues on the operating system level.
   - *Rejected*: Platform-specific (Linux-only, unavailable on macOS/BSD/Windows), requires root/CAP_NET_ADMIN privileges, cannot inspect tenant authentication identities or enforce per-tenant quotas.
3. **Native Pure-Rust Calendar & Time-of-Day Bandwidth Scheduler (Option BI)**:
   - Built-in, `#![forbid(unsafe_code)]` calendar and minute-accurate time window matching.
   - Multi-rule priority cascading with default fallback rates.
   - Pure-Rust civil time calculation from Unix timestamps without external dependencies like `chrono`.
   - Dynamic token-bucket refill rate adjustment in `RateLimiter`, `ScheduledBandwidthLimiter`, and `HierarchicalBandwidthAllocator` across rule transitions with zero connection drops.
   - Declarative configuration in `velcruxd` TOML (`[bandwidth]`, `[[bandwidth.rule]]`), SIGHUP hot reload, and CLI subcommands (`velcrux schedule inspect`, `velcrux schedule eval`, `--bandwidth-schedule`).

## Decision

Option 3. Velcrux implements a native, zero-dependency calendar and time-of-day bandwidth scheduling engine across `velcrux-core`, `velcrux-server`, and `velcrux-client`.

## Architecture & Implementation

### 1. Calendar Day-of-Week & Window Matchers

- **`DayOfWeek`**: ISO 8601 day representation (1 = Monday, 7 = Sunday) with full and short name parsing.
- **`DayMatcher`**:
  - `All` (`*` or `all`): Matches any day.
  - `Weekdays` (`Mon-Fri` or `weekdays`): Matches Monday through Friday.
  - `Weekend` (`Sat-Sun` or `weekend`): Matches Saturday and Sunday.
  - `Range(from, to)` (e.g. `Tue-Fri`): Matches inclusive contiguous day ranges, wrapping around Sunday if needed.
  - `List(days)` (e.g. `Mon,Wed,Fri`): Matches explicit day sets.
- **`TimeWindow`**:
  - Represents minute-of-day intervals $[0, 1439]$.
  - **Regular Windows** ($start \le end$, e.g. `09:00-17:00`): Active when $start \le m < end$.
  - **Overnight Windows** ($start > end$, e.g. `22:00-06:00`): Spans midnight, active when $m \ge start \lor m < end$.
  - Provides exact `minutes_until_boundary(m)` for countdown metrics.

### 2. Pure-Rust Civil Time Arithmetic

To maintain `#![forbid(unsafe_code)]` and zero external dependencies:
$$\text{local\_secs} = \text{epoch\_secs} + (\text{utc\_offset\_minutes} \times 60)$$
$$\text{seconds\_in\_day} = \text{local\_secs} \pmod{86400}$$
$$\text{hour} = \lfloor\text{seconds\_in\_day} / 3600\rfloor, \quad \text{minute} = \lfloor(\text{seconds\_in\_day} \pmod{3600}) / 60\rfloor$$
Because 1970-01-01 was Thursday (day 4), the ISO weekday index is:
$$\text{weekday} = ((\lfloor\text{local\_secs} / 86400\rfloor + 3) \pmod 7) + 1$$

### 3. Cascading Rule Evaluation & Dynamic Refill Rates

A `BandwidthSchedule` maintains an ordered list of `BandwidthScheduleRule` entries and a fallback `default_rate`.
- Evaluated first-match-wins at timestamp $t$.
- If a rule matches the active day and time window, its rate ceiling applies; otherwise, `default_rate` applies.
- `ScheduledBandwidthLimiter`, `HierarchicalBandwidthAllocator`, and `RateLimiter` resolve the effective rate in real time during `acquire()` and `consume()`:
  - If the rate changed across a minute boundary, the token bucket adjusts its refill speed instantaneously.
  - In-flight QUIC connections and bulk transfer streams smoothly accelerate or decelerate without TCP/QUIC resets.

### 4. Configuration & Runtime Management

- **Server TOML Configuration**:
  ```toml
  [bandwidth]
  default_limit = "1Gbps"
  timezone_offset_minutes = -300 # EST

  [[bandwidth.rule]]
  id = "business-hours"
  days = "Mon-Fri"
  start = "09:00"
  end = "17:00"
  limit = "50Mbps"

  [[bandwidth.rule]]
  id = "weekend-boost"
  days = "Sat,Sun"
  limit = "unlimited"
  ```
  Alternatively, shorthand multi-rule strings can be provided directly:
  ```toml
  [bandwidth]
  schedule = "Mon-Fri 09:00-17:00: 50Mbps; Sat-Sun: unlimited; default: 1Gbps"
  ```
- **Hot Reloading**: SIGHUP re-evaluates `[bandwidth]` rules and updates `LimitsManager` via `reload_with_schedule`, preserving accumulated tenant byte usage.
- **Client CLI**:
  - `velcrux schedule inspect [--schedule <RULES|FILE>] [--utc-offset <MINUTES>]`: Displays formatted rule table, current evaluation, active rate, and transition countdown.
  - `velcrux schedule eval [--schedule <RULES|FILE>] [--timestamp <SECS>]`: Evaluates schedule rate at any epoch timestamp.
  - `--bandwidth-schedule <RULES|FILE>`: Global client flag shaping transfers dynamically according to calendar policies.

## Consequences

- **Positive**:
  - Seamless, unattended bandwidth shaping aligning with business hours and ISP pricing.
  - Zero connection resets or transfer interruptions during rule transitions.
  - `#![forbid(unsafe_code)]` preserved with zero external date/time libraries.
  - Parity across human and machine-readable JSON interfaces.
- **Trade-offs**:
  - Timestamps with timezone offsets assume a fixed offset during execution (daylight saving transitions require adjusting the offset in configuration or reloading via SIGHUP).
