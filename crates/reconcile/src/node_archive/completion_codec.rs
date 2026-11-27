//! Allocation bounds apply while decoding and before every serialization write.
use crate::{ReconcileError, Result};
use serde::{
    de::{self, Deserialize, Deserializer, SeqAccess, Visitor},
    Serialize,
};
use std::{
    fmt,
    io::{self, Write},
    marker::PhantomData,
};
use sync_extend_core_model::ContentId;

pub(super) const MAX_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_OBJECTS: usize = MAX_BYTES / 4096 - 1;

struct LimitedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, part: &[u8]) -> io::Result<usize> {
        let needed = self
            .bytes
            .len()
            .checked_add(part.len())
            .filter(|size| *size <= self.maximum)
            .ok_or_else(|| io::Error::other("completion encoding byte budget"))?;
        if needed > self.bytes.capacity() {
            let target = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            self.bytes
                .try_reserve_exact(target - self.bytes.len())
                .map_err(|_| io::Error::other("completion encoding allocation budget"))?;
        }
        self.bytes.extend_from_slice(part);
        Ok(part.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn bytes<T: Serialize + ?Sized>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    if maximum == 0 || maximum > MAX_BYTES {
        return Err(ReconcileError::ResourceLimit(
            "completion encoding total budget",
        ));
    }
    let mut output = LimitedBytes {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(output.bytes)
}
struct LimitedHash {
    hasher: blake3::Hasher,
    remaining: usize,
}
impl Write for LimitedHash {
    fn write(&mut self, part: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(part.len())
            .ok_or_else(|| io::Error::other("completion membership hash byte budget"))?;
        self.hasher.update(part);
        Ok(part.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn digest<T: Serialize + ?Sized>(value: &T) -> Result<ContentId> {
    let mut output = LimitedHash {
        hasher: blake3::Hasher::new(),
        remaining: MAX_BYTES,
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(ContentId::from_hasher(&output.hasher))
}
pub(super) fn text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    struct Text;
    impl Visitor<'_> for Text {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("at most 255 UTF-8 bytes")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<String, E> {
            if value.len() > 255 {
                return Err(E::custom("completion string byte budget"));
            }
            Ok(value.to_owned())
        }
    }
    deserializer.deserialize_str(Text)
}
struct TextValue(String);
impl<'de> Deserialize<'de> for TextValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        text(d).map(Self)
    }
}
struct BoundedSequence<T, const MAX: usize>(PhantomData<T>);
impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedSequence<T, MAX> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at most {MAX} elements")
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Vec<T>, A::Error> {
        if sequence.size_hint().is_some_and(|count| count > MAX) {
            return Err(de::Error::custom("completion sequence count budget"));
        }
        let mut values = Vec::new();
        loop {
            if values.len() == MAX {
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("completion sequence count budget"));
                }
                break;
            }
            let Some(value) = sequence.next_element()? else {
                break;
            };
            values.push(value);
        }
        Ok(values)
    }
}
pub(super) fn components<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    let values = d.deserialize_seq(BoundedSequence::<TextValue, 128>(PhantomData))?;
    Ok(values.into_iter().map(|value| value.0).collect())
}
#[cfg(windows)]
pub(super) fn objects<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<super::completion::ObjectEvidence>, D::Error> {
    d.deserialize_seq(BoundedSequence::<
        super::completion::ObjectEvidence,
        MAX_OBJECTS,
    >(PhantomData))
}

pub(super) fn path_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    struct PathText;
    impl Visitor<'_> for PathText {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("at most 4096 UTF-8 bytes of an original absolute target path")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<String, E> {
            if value.len() > 4096 {
                return Err(E::custom("completion target path byte budget"));
            }
            Ok(value.to_owned())
        }
    }
    d.deserialize_str(PathText)
}

/// Syntax validation remains serde's job; this first scan bounds allocation
/// before any escaped string scratch buffer or nested value can be decoded.
pub(super) fn preflight_decode(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(ReconcileError::ResourceLimit(
            "completion decoding total byte budget",
        ));
    }
    let mut quoted = false;
    let mut escaped = false;
    let mut string_bytes = 0usize;
    let mut depth = 0usize;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
                continue;
            }
            string_bytes += 1;
            if string_bytes > 4096 * 6 {
                return Err(ReconcileError::ResourceLimit(
                    "completion encoded string budget before decode",
                ));
            }
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    string_bytes = 0;
                }
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 8 {
                        return Err(ReconcileError::ResourceLimit(
                            "completion nesting budget before decode",
                        ));
                    }
                }
                b']' | b'}' => {
                    depth = depth.checked_sub(1).ok_or(ReconcileError::Invariant(
                        "completion unexpected closing delimiter",
                    ))?;
                }
                _ => (),
            }
        }
    }
    if quoted || escaped || depth != 0 {
        return Err(ReconcileError::Invariant(
            "completion unterminated bounded encoding",
        ));
    }
    Ok(())
}
