//! Strongly typed identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl $name {
            pub fn new(v: i64) -> Self {
                Self(v)
            }
            pub fn get(self) -> i64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<i64> for $name {
            fn from(v: i64) -> Self {
                Self(v)
            }
        }
    };
}

id_newtype!(ProjectId);
id_newtype!(ExchangeId);
id_newtype!(CaptureSessionId);
id_newtype!(ReplyTabId);
id_newtype!(FuzzJobId);
id_newtype!(BrowserSessionId);
id_newtype!(BrowserActionId);
id_newtype!(AnnotationId);
id_newtype!(BodyId);
id_newtype!(FindingId);
