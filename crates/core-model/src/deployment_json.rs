//! One bounded decoder for deployment documents, including nested maps.
use crate::{ModelError, Result};
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_VALUES: usize = 100_000;
const MAX_DEPTH: usize = 32;

struct ValueSeed<'budget> {
    depth: usize,
    values: &'budget mut usize,
}
struct ValueVisitor<'budget> {
    depth: usize,
    values: &'budget mut usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = serde_json::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.values >= MAX_VALUES {
            return Err(serde::de::Error::custom("deployment JSON structure budget"));
        }
        *self.values += 1;
        decoder.deserialize_any(ValueVisitor {
            depth: self.depth,
            values: self.values,
        })
    }
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = serde_json::Value;
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("bounded deployment JSON with unique object keys")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(value.into())
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("nonfinite deployment number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(value.into())
    }
    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<Self::Value, E> {
        Ok(value.into())
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut result = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            depth: self.depth + 1,
            values: self.values,
        })? {
            result.push(value);
        }
        Ok(serde_json::Value::Array(result))
    }
    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut result = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 32_768 || result.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "duplicate or oversized deployment JSON key",
                ));
            }
            let value = map.next_value_seed(ValueSeed {
                depth: self.depth + 1,
                values: self.values,
            })?;
            result.insert(key, value);
        }
        Ok(serde_json::Value::Object(result))
    }
}

/// Byte, aggregate value and depth budgets apply before typed deserialization.
/// Repeated keys are rejected at every object/map layer.
pub fn decode_deployment_document<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T> {
    if maximum == 0 || maximum > MAX_BYTES || bytes.is_empty() || bytes.len() > maximum {
        return Err(ModelError::InvalidConfig(
            "bounded deployment document bytes",
        ));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut values = 0;
    let value = ValueSeed {
        depth: 0,
        values: &mut values,
    }
    .deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(serde_json::from_value(value)?)
}
