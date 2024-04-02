use once_cell::sync::Lazy;
use regex::Regex;
use snafu::ensure;

use crate::protocol::{
    BadNewIdentifierLengthSnafu, BadNewIdentifierNamespaceSnafu, BadNewIdentifierValueSnafu,
    PacketError, Result,
};

pub static NAMESPACE_RULES: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9\.\-_]+$").unwrap());
pub static VALUE_RULES: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9\.\-_\/]+$").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    namespace: String,
    value: String,
}

impl Identifier {
    pub fn new(namespace: String, value: String) -> Result<Self> {
        ensure!(
            NAMESPACE_RULES.is_match(&namespace),
            BadNewIdentifierNamespaceSnafu {
                namespace,
                sent_by_client: false
            }
        );

        ensure!(
            VALUE_RULES.is_match(&value),
            BadNewIdentifierValueSnafu {
                value,
                sent_by_client: false
            }
        );

        let identifier = Self { namespace, value };

        // < not <= to include the ':'
        ensure!(
            identifier.namespace.len() + identifier.value.len() < 32767,
            BadNewIdentifierLengthSnafu {
                identifier,
                sent_by_client: false
            }
        );

        Ok(identifier)
    }
}

impl From<Identifier> for String {
    fn from(identifier: Identifier) -> Self {
        (identifier.namespace + ":" + &identifier.value).to_string()
    }
}

impl TryFrom<String> for Identifier {
    type Error = PacketError;

    fn try_from(identifier: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let split: Vec<&str> = identifier.split(':').collect();

        let namespace: String;
        let value: String;

        match split.len() {
            1 => {
                namespace = "minecraft".into();
                value = split[0].into();
            }
            2 => {
                namespace = split[0].into();
                value = split[1].into();
            }
            _ => {
                return Err(PacketError::IdentifierStrangeColons {
                    identifier_raw: identifier,
                })
            }
        }

        Ok(Self { namespace, value })
    }
}
