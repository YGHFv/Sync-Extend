//! Bounded RFC 4918 If lists; tagged resources are resolved by the gateway.
use super::webdav_locks::valid_token;
use sync_extend_core_model::webdav::valid_etag;

pub struct Condition {
    pub negated: bool,
    pub value: String,
    pub etag: bool,
}
pub struct List {
    pub resource: Option<String>,
    pub conditions: Vec<Condition>,
}

pub fn parse(value: Option<&str>) -> Result<Vec<List>, ()> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_empty() || value.len() > 8192 || !value.is_ascii() {
        return Err(());
    }
    let mut parser = Parser {
        value: value.as_bytes(),
        offset: 0,
    };
    parser.spaces();
    let tagged = parser.peek() == Some(b'<');
    let mut resource = None;
    let mut lists = Vec::new();
    while parser.peek().is_some() {
        if tagged && parser.peek() == Some(b'<') {
            resource = Some(parser.delimited(b'<', b'>')?);
            parser.spaces();
            if parser.peek() != Some(b'(') {
                return Err(());
            }
        } else if tagged && resource.is_none() {
            return Err(());
        }
        if parser.peek() != Some(b'(') || lists.len() >= 32 {
            return Err(());
        }
        parser.offset += 1;
        parser.spaces();
        let mut conditions = Vec::new();
        while parser.peek() != Some(b')') {
            if parser.peek().is_none() || conditions.len() >= 32 {
                return Err(());
            }
            let negated = parser.value[parser.offset..].starts_with(b"Not ");
            if negated {
                parser.offset += 4;
                parser.spaces();
            }
            let etag = parser.peek() == Some(b'[');
            let value = if etag {
                parser.delimited(b'[', b']')?
            } else {
                parser.delimited(b'<', b'>')?
            };
            if (etag && !valid_etag(&value)) || (!etag && !valid_token(&value)) {
                return Err(());
            }
            conditions.push(Condition {
                negated,
                value,
                etag,
            });
            parser.spaces();
        }
        if conditions.is_empty() {
            return Err(());
        }
        parser.offset += 1;
        parser.spaces();
        lists.push(List {
            resource: resource.clone(),
            conditions,
        });
        if !tagged && parser.peek() == Some(b'<') {
            return Err(());
        }
    }
    Ok(lists)
}

struct Parser<'a> {
    value: &'a [u8],
    offset: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.value.get(self.offset).copied()
    }
    fn spaces(&mut self) {
        while self.peek().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            self.offset += 1;
        }
    }
    fn delimited(&mut self, begin: u8, end: u8) -> Result<String, ()> {
        if self.peek() != Some(begin) {
            return Err(());
        }
        self.offset += 1;
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte != end) {
            if self
                .peek()
                .is_some_and(|byte| byte.is_ascii_control() || byte == begin)
            {
                return Err(());
            }
            self.offset += 1;
        }
        if self.peek() != Some(end) || self.offset == start {
            return Err(());
        }
        let value = String::from_utf8(self.value[start..self.offset].to_vec()).map_err(|_| ())?;
        self.offset += 1;
        Ok(value)
    }
}
