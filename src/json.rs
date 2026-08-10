use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(object) => object.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.parse().ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    offset: usize,
    message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "JSON error at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for Error {}

pub fn parse(input: &str) -> Result<Value, Error> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        offset: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    if parser.offset != parser.bytes.len() {
        return parser.error("trailing characters");
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn error<T>(&self, message: &str) -> Result<T, Error> {
        Err(Error {
            offset: self.offset,
            message: message.to_owned(),
        })
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }

    fn value(&mut self) -> Result<Value, Error> {
        self.whitespace();
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            Some(_) => self.error("unexpected token"),
            None => self.error("unexpected end of input"),
        }
    }

    fn literal(&mut self, expected: &[u8], value: Value) -> Result<Value, Error> {
        if self.bytes.get(self.offset..self.offset + expected.len()) == Some(expected) {
            self.offset += expected.len();
            Ok(value)
        } else {
            self.error("invalid literal")
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        if self.take() != Some(b'"') {
            return self.error("expected string");
        }
        let mut output = String::new();
        let mut start = self.offset;
        loop {
            match self.take() {
                Some(b'"') => {
                    self.push_utf8(&mut output, start, self.offset - 1)?;
                    return Ok(output);
                }
                Some(b'\\') => {
                    self.push_utf8(&mut output, start, self.offset - 1)?;
                    match self.take() {
                        Some(b'"') => output.push('"'),
                        Some(b'\\') => output.push('\\'),
                        Some(b'/') => output.push('/'),
                        Some(b'b') => output.push('\u{0008}'),
                        Some(b'f') => output.push('\u{000c}'),
                        Some(b'n') => output.push('\n'),
                        Some(b'r') => output.push('\r'),
                        Some(b't') => output.push('\t'),
                        Some(b'u') => self.unicode_escape(&mut output)?,
                        _ => return self.error("invalid string escape"),
                    }
                    start = self.offset;
                }
                Some(0x00..=0x1f) => return self.error("control character in string"),
                Some(_) => {}
                None => return self.error("unterminated string"),
            }
        }
    }

    fn push_utf8(&self, output: &mut String, start: usize, end: usize) -> Result<(), Error> {
        let value = std::str::from_utf8(&self.bytes[start..end]).map_err(|_| Error {
            offset: start,
            message: "invalid UTF-8".to_owned(),
        })?;
        output.push_str(value);
        Ok(())
    }

    fn unicode_escape(&mut self, output: &mut String) -> Result<(), Error> {
        let first = self.hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if self.take() != Some(b'\\') || self.take() != Some(b'u') {
                return self.error("missing low surrogate");
            }
            let second = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return self.error("invalid low surrogate");
            }
            0x10000 + (((first - 0xd800) as u32) << 10) + (second - 0xdc00) as u32
        } else if (0xdc00..=0xdfff).contains(&first) {
            return self.error("unexpected low surrogate");
        } else {
            first as u32
        };
        let Some(character) = char::from_u32(scalar) else {
            return self.error("invalid Unicode scalar");
        };
        output.push(character);
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, Error> {
        let mut value = 0u16;
        for _ in 0..4 {
            value = value
                .checked_mul(16)
                .and_then(|current| {
                    self.take()
                        .and_then(hex)
                        .map(|digit| current + digit as u16)
                })
                .ok_or_else(|| Error {
                    offset: self.offset,
                    message: "invalid Unicode escape".to_owned(),
                })?;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<String, Error> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        match self.take() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return self.error("invalid number"),
        }
        if self.peek() == Some(b'.') {
            self.offset += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            self.digits()?;
        }
        Ok(String::from_utf8(self.bytes[start..self.offset].to_vec()).expect("ASCII number"))
    }

    fn digits(&mut self) -> Result<(), Error> {
        let start = self.offset;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        if start == self.offset {
            self.error("expected digit")
        } else {
            Ok(())
        }
    }

    fn array(&mut self) -> Result<Value, Error> {
        self.offset += 1;
        let mut values = Vec::new();
        self.whitespace();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            match self.take() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(values)),
                _ => return self.error("expected ',' or ']'"),
            }
        }
    }

    fn object(&mut self) -> Result<Value, Error> {
        self.offset += 1;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(Value::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            if self.take() != Some(b':') {
                return self.error("expected ':'");
            }
            values.insert(key, self.value()?);
            self.whitespace();
            match self.take() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(values)),
                _ => return self.error("expected ',' or '}'"),
            }
        }
    }
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04x}", value as u32);
            }
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_json_and_surrogates() {
        let value = parse(r#"{"message":"hello \uD83D\uDCA5","items":[1,true,null]}"#).unwrap();
        assert_eq!(
            value.get("message").and_then(Value::as_str),
            Some("hello 💥")
        );
        assert_eq!(
            value.get("items").and_then(Value::as_array).unwrap().len(),
            3
        );
    }

    #[test]
    fn rejects_trailing_input() {
        assert!(parse("{} nope").is_err());
    }
}
