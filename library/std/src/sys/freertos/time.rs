use crate::time::Duration;
use freertos_rust::*;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(Duration);

pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::from_secs(0));

impl Instant {
    // FreerRTOS provides a tick count and tick duration. We can use this to work out time since booting. FreeRTOS does not 
    // provide a time of day function (some boards have a real time clock, some do not. We can't assume it exists, and access
    // to any clock would be HAL-dependent.
    // By presenting time since boot (instead of time since epoch), we still can measure intervals, which is useful in the code.
    pub fn now() -> Instant {
        unsafe {
            Instant(Duration::from_millis((freertos_rs_xTaskGetTickCount() * freertos_rs_get_portTICK_PERIOD_MS()) as u64))
            //TODO: deal with arithmetic wraparound of freertos_rs_xTaskGetTickCount(), which occurs after 49 days.
        }
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        self.0.checked_sub(other.0)
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_add(*other)?))
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_sub(*other)?))
    }
}

impl SystemTime {
    // FreerRTOS provides a tick count and tick duration. We can use this to work out time since booting. FreeRTOS does not 
    // provide a time of day function (some boards have a real time clock, some do not. We can't assume it exists, and access
    // to any clock would be HAL-dependent.
    // By presenting time since boot (instead of time since epoch), we still can measure intervals, which is useful in the code.
    pub fn now() -> SystemTime {
        unsafe {
            SystemTime(Duration::from_millis((freertos_rs_xTaskGetTickCount() * freertos_rs_get_portTICK_PERIOD_MS()) as u64))
            //TODO: deal with arithmetic wraparound of freertos_rs_xTaskGetTickCount(), which occurs after 49 days.
        }
    }

    pub fn sub_time(&self, other: &SystemTime) -> Result<Duration, Duration> {
        self.0.checked_sub(other.0).ok_or_else(|| other.0 - self.0)
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<SystemTime> {
        Some(SystemTime(self.0.checked_add(*other)?))
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<SystemTime> {
        Some(SystemTime(self.0.checked_sub(*other)?))
    }
}
