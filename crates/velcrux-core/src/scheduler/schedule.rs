//! Calendar & Time-of-Day Bandwidth Scheduler (Option BI).
//!
//! (`REQUIREMENTS.md` §28; `OPERATIONS.md` §43).
//!
//! Provides dynamic, time-aware bandwidth shaping:
//! - Day-of-week matchers (`Mon-Fri`, `Sat,Sun`, `*`, `Weekdays`, `Weekend`).
//! - Minute-accurate time windows (`09:00-17:00`, overnight windows like `22:00-06:00`).
//! - Cascading rule evaluation with default rate fallbacks.
//! - Seamless dynamic token-bucket rate adjustment as time crosses rule boundaries
//!   with zero connection restarts or transfer interruptions.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::fairness::{BandwidthRate, TokenBucket};

// ---------------------------------------------------------------------------
// Day of Week
// ---------------------------------------------------------------------------

/// Day of the week (ISO 8601: Monday = 1, Sunday = 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DayOfWeek {
    Monday = 1,
    Tuesday = 2,
    Wednesday = 3,
    Thursday = 4,
    Friday = 5,
    Saturday = 6,
    Sunday = 7,
}

impl DayOfWeek {
    /// Return the 1-based ISO weekday number (1 = Monday, 7 = Sunday).
    pub fn number(&self) -> u8 {
        *self as u8
    }

    /// Construct from 1-based ISO weekday number.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Monday),
            2 => Some(Self::Tuesday),
            3 => Some(Self::Wednesday),
            4 => Some(Self::Thursday),
            5 => Some(Self::Friday),
            6 => Some(Self::Saturday),
            7 => Some(Self::Sunday),
            _ => None,
        }
    }

    /// Short 3-letter name (e.g. "Mon").
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Monday => "Mon",
            Self::Tuesday => "Tue",
            Self::Wednesday => "Wed",
            Self::Thursday => "Thu",
            Self::Friday => "Fri",
            Self::Saturday => "Sat",
            Self::Sunday => "Sun",
        }
    }

    /// Full English name (e.g. "Monday").
    pub fn name(&self) -> &'static str {
        match self {
            Self::Monday => "Monday",
            Self::Tuesday => "Tuesday",
            Self::Wednesday => "Wednesday",
            Self::Thursday => "Thursday",
            Self::Friday => "Friday",
            Self::Saturday => "Saturday",
            Self::Sunday => "Sunday",
        }
    }

    /// Whether this day is a weekday (Monday–Friday).
    pub fn is_weekday(&self) -> bool {
        matches!(
            self,
            Self::Monday | Self::Tuesday | Self::Wednesday | Self::Thursday | Self::Friday
        )
    }

    /// Whether this day is on the weekend (Saturday or Sunday).
    pub fn is_weekend(&self) -> bool {
        matches!(self, Self::Saturday | Self::Sunday)
    }

    /// Next day of week.
    pub fn next(&self) -> Self {
        match self {
            Self::Monday => Self::Tuesday,
            Self::Tuesday => Self::Wednesday,
            Self::Wednesday => Self::Thursday,
            Self::Thursday => Self::Friday,
            Self::Friday => Self::Saturday,
            Self::Saturday => Self::Sunday,
            Self::Sunday => Self::Monday,
        }
    }
}

impl fmt::Display for DayOfWeek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

impl FromStr for DayOfWeek {
    type Err = ParseScheduleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "mon" | "monday" => Ok(Self::Monday),
            "tue" | "tues" | "tuesday" => Ok(Self::Tuesday),
            "wed" | "wednesday" => Ok(Self::Wednesday),
            "thu" | "thur" | "thurs" | "thursday" => Ok(Self::Thursday),
            "fri" | "friday" => Ok(Self::Friday),
            "sat" | "saturday" => Ok(Self::Saturday),
            "sun" | "sunday" => Ok(Self::Sunday),
            other => Err(ParseScheduleError(format!("unknown day of week '{other}'"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Day Matcher
// ---------------------------------------------------------------------------

/// Matches one or more days of the week.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayMatcher {
    /// Matches every day of the week (`*` or `all`).
    All,
    /// Matches Monday through Friday (`Mon-Fri` or `weekdays`).
    Weekdays,
    /// Matches Saturday and Sunday (`Sat-Sun` or `weekend`).
    Weekend,
    /// Matches a contiguous range of days (e.g. `Tue-Fri`).
    Range(DayOfWeek, DayOfWeek),
    /// Matches an explicit list of days (e.g. `Mon,Wed,Fri`).
    List(Vec<DayOfWeek>),
}

impl DayMatcher {
    /// Test whether this matcher includes `day`.
    pub fn matches(&self, day: DayOfWeek) -> bool {
        match self {
            Self::All => true,
            Self::Weekdays => day.is_weekday(),
            Self::Weekend => day.is_weekend(),
            Self::Range(from, to) => {
                let start = from.number();
                let end = to.number();
                let target = day.number();
                if start <= end {
                    target >= start && target <= end
                } else {
                    // Wrap-around range e.g. Fri-Mon
                    target >= start || target <= end
                }
            }
            Self::List(days) => days.contains(&day),
        }
    }
}

impl fmt::Display for DayMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "*"),
            Self::Weekdays => write!(f, "Mon-Fri"),
            Self::Weekend => write!(f, "Sat-Sun"),
            Self::Range(from, to) => write!(f, "{from}-{to}"),
            Self::List(days) => {
                let parts: Vec<&str> = days.iter().map(|d| d.short_name()).collect();
                write!(f, "{}", parts.join(","))
            }
        }
    }
}

impl FromStr for DayMatcher {
    type Err = ParseScheduleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed == "*" || trimmed.eq_ignore_ascii_case("all") || trimmed.eq_ignore_ascii_case("everyday") {
            return Ok(Self::All);
        }
        if trimmed.eq_ignore_ascii_case("weekdays") || trimmed.eq_ignore_ascii_case("mon-fri") {
            return Ok(Self::Weekdays);
        }
        if trimmed.eq_ignore_ascii_case("weekend") || trimmed.eq_ignore_ascii_case("sat-sun") {
            return Ok(Self::Weekend);
        }

        if let Some((from_str, to_str)) = trimmed.split_once('-') {
            let from = DayOfWeek::from_str(from_str)?;
            let to = DayOfWeek::from_str(to_str)?;
            return Ok(Self::Range(from, to));
        }

        if trimmed.contains(',') {
            let mut days = Vec::new();
            for part in trimmed.split(',') {
                let day = DayOfWeek::from_str(part)?;
                if !days.contains(&day) {
                    days.push(day);
                }
            }
            if days.is_empty() {
                return Err(ParseScheduleError("empty day list".into()));
            }
            return Ok(Self::List(days));
        }

        // Single day
        let day = DayOfWeek::from_str(trimmed)?;
        Ok(Self::List(vec![day]))
    }
}

// ---------------------------------------------------------------------------
// Time Window
// ---------------------------------------------------------------------------

/// A time-of-day interval specified in minutes from midnight (0..=1439).
/// Supports both regular windows (e.g. 09:00 to 17:00) and overnight
/// windows spanning midnight (e.g. 22:00 to 06:00).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start minute of day (0..=1439, inclusive).
    pub start_minute: u16,
    /// End minute of day (0..=1439, exclusive).
    pub end_minute: u16,
}

impl TimeWindow {
    /// Construct a new TimeWindow with explicit start and end minutes.
    pub fn new(start_minute: u16, end_minute: u16) -> Result<Self, ParseScheduleError> {
        if start_minute >= 1440 {
            return Err(ParseScheduleError(format!(
                "start minute {start_minute} exceeds 1439"
            )));
        }
        if end_minute >= 1440 {
            return Err(ParseScheduleError(format!(
                "end minute {end_minute} exceeds 1439"
            )));
        }
        if start_minute == end_minute {
            return Err(ParseScheduleError(
                "start and end time cannot be identical in window".into(),
            ));
        }
        Ok(Self {
            start_minute,
            end_minute,
        })
    }

    /// Construct from hour and minute components.
    pub fn from_hm(sh: u8, sm: u8, eh: u8, em: u8) -> Result<Self, ParseScheduleError> {
        if sh >= 24 || eh >= 24 || sm >= 60 || em >= 60 {
            return Err(ParseScheduleError("invalid HH:MM specification".into()));
        }
        Self::new((sh as u16) * 60 + (sm as u16), (eh as u16) * 60 + (em as u16))
    }

    /// Whether this window spans past midnight (start > end).
    pub fn spans_midnight(&self) -> bool {
        self.start_minute > self.end_minute
    }

    /// Check if `minute_of_day` (0..1439) falls inside this window.
    pub fn contains(&self, minute_of_day: u16) -> bool {
        if self.start_minute < self.end_minute {
            // Normal intra-day window, e.g. 09:00 - 17:00
            minute_of_day >= self.start_minute && minute_of_day < self.end_minute
        } else {
            // Overnight window spanning midnight, e.g. 22:00 - 06:00
            minute_of_day >= self.start_minute || minute_of_day < self.end_minute
        }
    }

    /// Number of minutes until the next boundary change (entering or leaving the window).
    pub fn minutes_until_boundary(&self, minute_of_day: u16) -> u16 {
        let inside = self.contains(minute_of_day);
        let target = if inside {
            self.end_minute
        } else {
            self.start_minute
        };

        if target >= minute_of_day {
            target - minute_of_day
        } else {
            (1440 - minute_of_day) + target
        }
    }
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sh = self.start_minute / 60;
        let sm = self.start_minute % 60;
        let eh = self.end_minute / 60;
        let em = self.end_minute % 60;
        write!(f, "{sh:02}:{sm:02}-{eh:02}:{em:02}")
    }
}

impl FromStr for TimeWindow {
    type Err = ParseScheduleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let (start_str, end_str) = trimmed
            .split_once('-')
            .ok_or_else(|| ParseScheduleError(format!("missing '-' in time window '{trimmed}'")))?;

        let parse_hm = |val: &str| -> Result<(u8, u8), ParseScheduleError> {
            let (h_str, m_str) = val
                .split_once(':')
                .ok_or_else(|| ParseScheduleError(format!("missing ':' in time '{val}'")))?;
            let h = h_str
                .trim()
                .parse::<u8>()
                .map_err(|_| ParseScheduleError(format!("invalid hour '{h_str}'")))?;
            let m = m_str
                .trim()
                .parse::<u8>()
                .map_err(|_| ParseScheduleError(format!("invalid minute '{m_str}'")))?;
            if h >= 24 || m >= 60 {
                return Err(ParseScheduleError(format!("time {h:02}:{m:02} out of range")));
            }
            Ok((h, m))
        };

        let (sh, sm) = parse_hm(start_str)?;
        let (eh, em) = parse_hm(end_str)?;
        Self::from_hm(sh, sm, eh, em)
    }
}

// ---------------------------------------------------------------------------
// Schedule Rule
// ---------------------------------------------------------------------------

/// An individual bandwidth schedule rule matching day and time constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthScheduleRule {
    /// Human-readable identifier or tag (e.g. "business-hours").
    pub id: String,
    /// Days of week filter.
    pub days: DayMatcher,
    /// Optional time-of-day window (None matches all 24 hours of matching days).
    pub time: Option<TimeWindow>,
    /// Target bandwidth ceiling to apply during active window.
    pub rate: BandwidthRate,
    /// Optional descriptive note.
    pub description: String,
}

impl BandwidthScheduleRule {
    /// Test whether this rule applies at the given weekday and minute of day.
    pub fn matches(&self, day: DayOfWeek, minute_of_day: u16) -> bool {
        if !self.days.matches(day) {
            return false;
        }
        match self.time {
            Some(ref window) => window.contains(minute_of_day),
            None => true,
        }
    }
}

impl fmt::Display for BandwidthScheduleRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.days)?;
        if let Some(ref window) = self.time {
            write!(f, " {window}")?;
        }
        write!(f, ": {}", self.rate)
    }
}

impl FromStr for BandwidthScheduleRule {
    type Err = ParseScheduleError;

    /// Parse rule format:
    /// `"[id=name] <days> [HH:MM-HH:MM]: <rate> [# description]"`
    ///
    /// Examples:
    /// - `"Mon-Fri 09:00-17:00: 50Mbps"`
    /// - `"Sat,Sun: unlimited # Weekend uncapped"`
    /// - `"22:00-06:00: 5Gbps"`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let (content, description) = if let Some((left, comment)) = trimmed.split_once('#') {
            (left.trim(), comment.trim().to_string())
        } else {
            (trimmed, String::new())
        };

        let (pattern_part, rate_part) = content.rsplit_once(':').ok_or_else(|| {
            ParseScheduleError(format!("missing ':' separating pattern and rate in '{content}'"))
        })?;

        let rate = BandwidthRate::from_str(rate_part.trim()).map_err(|e| {
            ParseScheduleError(format!("invalid rate in schedule rule: {}", e.0))
        })?;

        let mut tokens = pattern_part.split_whitespace();
        let first = tokens
            .next()
            .ok_or_else(|| ParseScheduleError("empty pattern in schedule rule".into()))?;

        let mut id = String::new();
        let (days_str, time_str) = if first.starts_with('[') && first.ends_with(']') {
            let inner = &first[1..first.len() - 1];
            if let Some((k, v)) = inner.split_once('=') {
                if k.trim().eq_ignore_ascii_case("id") {
                    id = v.trim().to_string();
                }
            }
            let d = tokens
                .next()
                .ok_or_else(|| ParseScheduleError("missing day pattern after [id=...]".into()))?;
            let t = tokens.next();
            (d, t)
        } else {
            (first, tokens.next())
        };

        // Check if first token is actually a time window without days (implicitly all days)
        let (days, time) = if days_str.contains(':') && days_str.contains('-') {
            let window = TimeWindow::from_str(days_str)?;
            (DayMatcher::All, Some(window))
        } else {
            let days = DayMatcher::from_str(days_str)?;
            let time = match time_str {
                Some(ts) => Some(TimeWindow::from_str(ts)?),
                None => None,
            };
            (days, time)
        };

        if id.is_empty() {
            id = format!("{days}{}", time.map(|t| format!("_{t}")).unwrap_or_default());
        }

        Ok(Self {
            id,
            days,
            time,
            rate,
            description,
        })
    }
}

// ---------------------------------------------------------------------------
// Schedule & Active Status
// ---------------------------------------------------------------------------

/// Runtime status of a bandwidth schedule evaluation at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveScheduleStatus {
    /// Active effective bandwidth rate.
    pub active_rate: BandwidthRate,
    /// ID of the matching schedule rule (None if defaulting).
    pub matching_rule_id: Option<String>,
    /// Description of the matching rule.
    pub matching_rule_desc: Option<String>,
    /// Whether the active rate comes from fallback default rate.
    pub is_default: bool,
    /// Current evaluated local day of week.
    pub day: DayOfWeek,
    /// Current evaluated local hour of day (0..=23).
    pub hour: u8,
    /// Current evaluated local minute of hour (0..=59).
    pub minute: u8,
    /// Seconds remaining until next rule transition boundary.
    pub seconds_until_transition: u64,
}

/// A complete calendar and time-of-day bandwidth scheduling policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthSchedule {
    /// Ordered list of schedule rules evaluated first-match-wins.
    pub rules: Vec<BandwidthScheduleRule>,
    /// Baseline fallback rate applied when no rules match (default: unlimited).
    pub default_rate: BandwidthRate,
    /// Timezone offset from UTC in minutes (default: 0).
    pub utc_offset_minutes: i32,
}

impl Default for BandwidthSchedule {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_rate: BandwidthRate::UNLIMITED,
            utc_offset_minutes: 0,
        }
    }
}

impl BandwidthSchedule {
    /// Create a new schedule with a fallback default rate.
    pub fn new(default_rate: BandwidthRate) -> Self {
        Self {
            rules: Vec::new(),
            default_rate,
            utc_offset_minutes: 0,
        }
    }

    /// Add a schedule rule to the end of the priority chain.
    pub fn add_rule(&mut self, rule: BandwidthScheduleRule) {
        self.rules.push(rule);
    }

    /// Set UTC offset in minutes (e.g. -300 for EST, +330 for IST).
    pub fn with_utc_offset(mut self, minutes: i32) -> Self {
        self.utc_offset_minutes = minutes.clamp(-720, 840);
        self
    }

    /// Resolve active bandwidth limit and transition metrics at given Unix timestamp.
    pub fn resolve_at(&self, timestamp_secs: u64) -> ActiveScheduleStatus {
        let (day, hour, minute, second) =
            civil_time_from_timestamp(timestamp_secs, self.utc_offset_minutes);
        let minute_of_day = (hour as u16) * 60 + (minute as u16);

        // Find first matching rule
        let mut matched = None;
        for rule in &self.rules {
            if rule.matches(day, minute_of_day) {
                matched = Some(rule);
                break;
            }
        }

        let (active_rate, matching_rule_id, matching_rule_desc, is_default) = match matched {
            Some(rule) => (
                rule.rate,
                Some(rule.id.clone()),
                if rule.description.is_empty() {
                    None
                } else {
                    Some(rule.description.clone())
                },
                false,
            ),
            None => (self.default_rate, None, None, true),
        };

        // Calculate seconds until next transition boundary by checking ahead
        let seconds_until_transition =
            self.calculate_seconds_to_next_transition(timestamp_secs, active_rate, second);

        ActiveScheduleStatus {
            active_rate,
            matching_rule_id,
            matching_rule_desc,
            is_default,
            day,
            hour,
            minute,
            seconds_until_transition,
        }
    }

    /// Evaluate schedule at the current system time.
    pub fn resolve_current(&self) -> ActiveScheduleStatus {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.resolve_at(now_secs)
    }

    /// Check subsequent boundary candidate points to find exact seconds until rate changes.
    fn calculate_seconds_to_next_transition(
        &self,
        now_secs: u64,
        current_rate: BandwidthRate,
        current_second: u8,
    ) -> u64 {
        if self.rules.is_empty() {
            return 86400 * 7; // No rules, stable indefinitely
        }

        // Test forward minute by minute up to 7 days
        // To be fast, check every minute for next 24 hours, then every 15 min for 7 days
        let seconds_to_next_minute = 60u64.saturating_sub(current_second as u64).max(1);
        let mut check_secs = now_secs + seconds_to_next_minute;

        for step in 1..=1440 {
            let (d, h, m, _) = civil_time_from_timestamp(check_secs, self.utc_offset_minutes);
            let mod_min = (h as u16) * 60 + (m as u16);
            let next_rate = self.rate_for(d, mod_min);
            if next_rate != current_rate {
                return (step as u64 - 1) * 60 + seconds_to_next_minute;
            }
            check_secs += 60;
        }

        // Next 6 days in 15-minute steps
        for step in 1..=(6 * 24 * 4) {
            let (d, h, m, _) = civil_time_from_timestamp(check_secs, self.utc_offset_minutes);
            let mod_min = (h as u16) * 60 + (m as u16);
            let next_rate = self.rate_for(d, mod_min);
            if next_rate != current_rate {
                return 86400 + (step as u64 - 1) * 900;
            }
            check_secs += 900;
        }

        86400 * 7
    }

    fn rate_for(&self, day: DayOfWeek, minute_of_day: u16) -> BandwidthRate {
        for rule in &self.rules {
            if rule.matches(day, minute_of_day) {
                return rule.rate;
            }
        }
        self.default_rate
    }
}

impl fmt::Display for BandwidthSchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rules.is_empty() {
            write!(f, "default: {}", self.default_rate)?;
        } else {
            let rule_strs: Vec<String> = self.rules.iter().map(|r| r.to_string()).collect();
            write!(f, "{}; default: {}", rule_strs.join("; "), self.default_rate)?;
        }
        if self.utc_offset_minutes != 0 {
            write!(f, " [UTC{:+03}:{:02}]", self.utc_offset_minutes / 60, (self.utc_offset_minutes % 60).abs())?;
        }
        Ok(())
    }
}

impl FromStr for BandwidthSchedule {
    type Err = ParseScheduleError;

    /// Parse schedule containing multiple semicolon-separated rules.
    ///
    /// Example:
    /// `"Mon-Fri 09:00-17:00: 50Mbps; Sat-Sun: unlimited; default: 1Gbps"`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut schedule = Self::default();
        let parts = s.split(|c| c == ';' || c == '\n');

        for raw_part in parts {
            let part = raw_part.trim();
            if part.is_empty() {
                continue;
            }

            // Check for default rate specification
            if let Some((k, v)) = part.split_once(':') {
                if k.trim().eq_ignore_ascii_case("default") {
                    let rate = BandwidthRate::from_str(v.trim()).map_err(|e| {
                        ParseScheduleError(format!("invalid default rate: {}", e.0))
                    })?;
                    schedule.default_rate = rate;
                    continue;
                }
            }

            // Otherwise, parse as schedule rule
            let rule = BandwidthScheduleRule::from_str(part)?;
            schedule.add_rule(rule);
        }

        Ok(schedule)
    }
}

// ---------------------------------------------------------------------------
// Scheduled Bandwidth Limiter
// ---------------------------------------------------------------------------

/// Thread-safe active bandwidth limiter driven by a calendar schedule.
/// Dynamically updates token-bucket rate on the fly as time boundaries cross.
#[derive(Debug)]
pub struct ScheduledBandwidthLimiter {
    schedule: BandwidthSchedule,
    bucket: Mutex<TokenBucket>,
    last_evaluated_rate: Mutex<BandwidthRate>,
}

impl ScheduledBandwidthLimiter {
    /// Create a new scheduled limiter.
    pub fn new(schedule: BandwidthSchedule) -> Self {
        let initial_status = schedule.resolve_current();
        let initial_rate = initial_status.active_rate;
        Self {
            schedule,
            bucket: Mutex::new(TokenBucket::new(initial_rate)),
            last_evaluated_rate: Mutex::new(initial_rate),
        }
    }

    /// Get current active schedule status.
    pub fn status(&self) -> ActiveScheduleStatus {
        self.schedule.resolve_current()
    }

    /// Access reference to underlying schedule.
    pub fn schedule(&self) -> &BandwidthSchedule {
        &self.schedule
    }

    /// Consume tokens for `bytes` at specified Unix timestamp, dynamically adjusting rate if needed.
    /// Returns async throttle duration if tokens are deficient.
    pub fn consume_at(&self, bytes: usize, timestamp_secs: u64) -> Duration {
        let current_status = self.schedule.resolve_at(timestamp_secs);
        let active_rate = current_status.active_rate;

        let mut bucket = self.bucket.lock().unwrap();
        let mut last_rate = self.last_evaluated_rate.lock().unwrap();

        if *last_rate != active_rate {
            bucket.set_rate(active_rate);
            *last_rate = active_rate;
        }

        bucket.consume(bytes)
    }

    /// Consume tokens at current system time.
    pub fn consume(&self, bytes: usize) -> Duration {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.consume_at(bytes, now_secs)
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust Civil Time Calculation from Unix Timestamp
// ---------------------------------------------------------------------------

/// Calculate local (DayOfWeek, Hour, Minute, Second) from Unix timestamp with UTC offset.
/// Pure integer arithmetic without external crates.
pub fn civil_time_from_timestamp(timestamp_secs: u64, utc_offset_minutes: i32) -> (DayOfWeek, u8, u8, u8) {
    let offset_secs = (utc_offset_minutes as i64) * 60;
    let local_secs = (timestamp_secs as i64) + offset_secs;

    let seconds_in_day = local_secs.rem_euclid(86400) as u32;
    let hour = (seconds_in_day / 3600) as u8;
    let minute = ((seconds_in_day % 3600) / 60) as u8;
    let second = (seconds_in_day % 60) as u8;

    let days_since_epoch = local_secs.div_euclid(86400);
    // 1970-01-01 was Thursday (index 4)
    let weekday_num = ((days_since_epoch + 3).rem_euclid(7)) + 1;
    let day = DayOfWeek::from_u8(weekday_num as u8).unwrap_or(DayOfWeek::Thursday);

    (day, hour, minute, second)
}

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseScheduleError(pub String);

impl fmt::Display for ParseScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid bandwidth schedule: {}", self.0)
    }
}

impl std::error::Error for ParseScheduleError {}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_day_of_week_properties() {
        assert_eq!(DayOfWeek::Monday.number(), 1);
        assert_eq!(DayOfWeek::Sunday.number(), 7);
        assert!(DayOfWeek::Wednesday.is_weekday());
        assert!(!DayOfWeek::Wednesday.is_weekend());
        assert!(DayOfWeek::Saturday.is_weekend());
        assert_eq!(DayOfWeek::Sunday.next(), DayOfWeek::Monday);
        assert_eq!(DayOfWeek::from_str("fri").unwrap(), DayOfWeek::Friday);
        assert_eq!(DayOfWeek::from_str("Tuesday").unwrap(), DayOfWeek::Tuesday);
    }

    #[test]
    fn test_day_matcher_parsing_and_matching() {
        let all = DayMatcher::from_str("*").unwrap();
        assert!(all.matches(DayOfWeek::Monday));
        assert!(all.matches(DayOfWeek::Sunday));

        let weekdays = DayMatcher::from_str("Mon-Fri").unwrap();
        assert!(weekdays.matches(DayOfWeek::Monday));
        assert!(weekdays.matches(DayOfWeek::Friday));
        assert!(!weekdays.matches(DayOfWeek::Saturday));

        let weekend = DayMatcher::from_str("Sat,Sun").unwrap();
        assert!(!weekend.matches(DayOfWeek::Friday));
        assert!(weekend.matches(DayOfWeek::Saturday));
        assert!(weekend.matches(DayOfWeek::Sunday));

        let custom_range = DayMatcher::from_str("Tue-Thu").unwrap();
        assert!(!custom_range.matches(DayOfWeek::Monday));
        assert!(custom_range.matches(DayOfWeek::Wednesday));
        assert!(!custom_range.matches(DayOfWeek::Friday));
    }

    #[test]
    fn test_time_window_regular_and_overnight() {
        // Regular 09:00 - 17:00
        let win = TimeWindow::from_str("09:00-17:00").unwrap();
        assert_eq!(win.start_minute, 540);
        assert_eq!(win.end_minute, 1020);
        assert!(!win.spans_midnight());
        assert!(!win.contains(539)); // 08:59
        assert!(win.contains(540));  // 09:00
        assert!(win.contains(720));  // 12:00
        assert!(win.contains(1019)); // 16:59
        assert!(!win.contains(1020)); // 17:00

        // Overnight 22:00 - 06:00
        let overnight = TimeWindow::from_str("22:00-06:00").unwrap();
        assert_eq!(overnight.start_minute, 1320);
        assert_eq!(overnight.end_minute, 360);
        assert!(overnight.spans_midnight());
        assert!(!overnight.contains(1319)); // 21:59
        assert!(overnight.contains(1320));  // 22:00
        assert!(overnight.contains(1400));  // 23:20
        assert!(overnight.contains(0));     // 00:00
        assert!(overnight.contains(359));   // 05:59
        assert!(!overnight.contains(360));  // 06:00
    }

    #[test]
    fn test_schedule_rule_parsing_and_evaluation() {
        let rule = BandwidthScheduleRule::from_str("Mon-Fri 09:00-17:00: 50Mbps # Business throttle").unwrap();
        assert_eq!(rule.days, DayMatcher::Weekdays);
        assert_eq!(rule.rate, BandwidthRate::from_bps(50_000_000));
        assert_eq!(rule.description, "Business throttle");

        assert!(rule.matches(DayOfWeek::Monday, 600)); // Mon 10:00
        assert!(!rule.matches(DayOfWeek::Monday, 400)); // Mon 06:40
        assert!(!rule.matches(DayOfWeek::Saturday, 600)); // Sat 10:00
    }

    #[test]
    fn test_bandwidth_schedule_multi_rule_resolution() {
        let schedule_str = "Mon-Fri 09:00-17:00: 50Mbps; Sat-Sun: unlimited; 22:00-06:00: 10Gbps; default: 1Gbps";
        let schedule = BandwidthSchedule::from_str(schedule_str).unwrap();

        // Check fallback default
        assert_eq!(schedule.default_rate, BandwidthRate::from_bps(1_000_000_000));
        assert_eq!(schedule.rules.len(), 3);

        // Wednesday 10:00 (minute 600) -> should match 50Mbps business rule
        // Timestamp 2026-10-14 10:00:00 UTC = 1791972000
        let (d, h, m, _) = civil_time_from_timestamp(1791972000, 0);
        assert_eq!(d, DayOfWeek::Wednesday);
        assert_eq!(h, 10);
        assert_eq!(m, 0);

        let status = schedule.resolve_at(1791972000);
        assert_eq!(status.active_rate, BandwidthRate::from_bps(50_000_000));
        assert!(!status.is_default);

        // Wednesday 19:00 (minute 1140) -> falls outside business window & before 22:00 -> default 1Gbps
        let status_evening = schedule.resolve_at(1791972000 + 9 * 3600);
        assert_eq!(status_evening.active_rate, BandwidthRate::from_bps(1_000_000_000));
        assert!(status_evening.is_default);

        // Wednesday 23:00 (minute 1380) -> matches overnight 10Gbps
        let status_night = schedule.resolve_at(1791972000 + 13 * 3600);
        assert_eq!(status_night.active_rate, BandwidthRate::from_bps(10_000_000_000));
        assert!(!status_night.is_default);

        // Saturday 12:00 -> matches weekend unlimited
        let status_weekend = schedule.resolve_at(1791972000 + 3 * 86400 + 2 * 3600);
        assert_eq!(status_weekend.active_rate, BandwidthRate::UNLIMITED);
    }

    #[test]
    fn test_scheduled_bandwidth_limiter_dynamic_transition() {
        // Schedule: Mon-Fri 09:00-17:00: 10KB/s (10240 B/s); default: unlimited
        let schedule_str = "Mon-Fri 09:00-17:00: 10240B/s; default: unlimited";
        let schedule = BandwidthSchedule::from_str(schedule_str).unwrap();
        let limiter = ScheduledBandwidthLimiter::new(schedule);

        // At 10:00: throttled to 10240 B/s
        let ts_peak = 1791972000;
        let delay_peak = limiter.consume_at(20480, ts_peak);
        assert!(delay_peak > Duration::ZERO);

        // At 20:00: unlimited -> zero delay
        let ts_offpeak = ts_peak + 10 * 3600;
        let delay_offpeak = limiter.consume_at(100_000_000, ts_offpeak);
        assert_eq!(delay_offpeak, Duration::ZERO);
    }
}
