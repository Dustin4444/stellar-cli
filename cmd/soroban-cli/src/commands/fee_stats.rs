// Deprecated: This module delegates to `fees::stats`. Use `stellar fees stats` instead.

use crate::commands::fees::stats;

pub use stats::Error;

pub type Cmd = stats::Cmd;
