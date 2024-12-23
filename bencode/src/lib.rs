pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    MissingKey,
    InvalidData,
    UnexpectedEOF,
    EOF,
    Other,
}

struct ErrorContext {
    lines: Vec<String>,
}

pub struct Error {
    kind: ErrorKind,
    context: Option<Box<ErrorContext>>,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Error2");
        s.field("kind", &self.kind);
        if let Some(ctx) = &self.context {
            s.field("context", &ctx.lines);
        }
        s.finish()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error: {:?}", self.kind)?;
        if let Some(ctx) = &self.context {
            for line in ctx.lines.iter().rev() {
                writeln!(f, "\t{}", line)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl Error {
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    fn missing_key(key: impl Into<String>) -> Self {
        let mut err = Self::new(ErrorKind::MissingKey);
        err.add_context(key.into());
        err
    }

    pub fn message(msg: impl Into<String>) -> Self {
        let mut err = Self::new(ErrorKind::Other);
        err.add_context(msg.into());
        err
    }

    fn add_context(&mut self, msg: String) {
        match &mut self.context {
            Some(ctx) => ctx.lines.push(msg),
            None => self.context = Some(Box::new(ErrorContext { lines: vec![msg] })),
        }
    }
}

pub trait Context<T> {
    fn context(self, context: &str) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T> Context<T> for Result<T> {
    fn context(mut self, context: &str) -> Result<T> {
        if let Err(ref mut error) = self {
            error.add_context(context.to_string());
        }
        self
    }

    fn with_context<F: FnOnce() -> String>(mut self, f: F) -> Result<T> {
        if let Err(ref mut error) = self {
            error.add_context(f());
        }
        self
    }
}

struct TryDisplayUtf8<'a>(&'a [u8]);

impl<'a> std::fmt::Display for TryDisplayUtf8<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.0) {
            Ok(str) => f.write_str(str),
            _ => write!(f, "{:?}", self.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenData<'a> {
    Integer(&'a [u8]),
    ByteString(&'a [u8]),
    ListBegin,
    DictBegin,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'a> {
    pub offset: usize,
    pub length: usize,
    pub data: TokenData<'a>,
}

#[derive(Debug, Clone)]
pub struct Tokenizer<'a> {
    data: &'a [u8],
    offset: usize,
    ahead: Option<Token<'a>>,
}

impl<'a> Tokenizer<'a> {
    pub fn new(data: &'a [u8]) -> Tokenizer<'a> {
        Tokenizer {
            data,
            offset: 0,
            ahead: None,
        }
    }

    pub fn next(&mut self) -> Result<Token<'a>> {
        if let Some(token) = self.ahead.take() {
            return Ok(token);
        }

        let peek = self.peek_one()?;
        match peek {
            b'i' => self.decode_integer(),
            b'0'..=b'9' => self.decode_string(),
            b'l' => {
                let token = Token {
                    offset: self.offset,
                    length: 1,
                    data: TokenData::ListBegin,
                };
                self.offset += 1;
                Ok(token)
            }
            b'd' => {
                let token = Token {
                    offset: self.offset,
                    length: 1,
                    data: TokenData::DictBegin,
                };
                self.offset += 1;
                Ok(token)
            }
            b'e' => {
                let token = Token {
                    offset: self.offset,
                    length: 1,
                    data: TokenData::End,
                };
                self.offset += 1;
                Ok(token)
            }
            _ => Err(Error::new(ErrorKind::InvalidData)),
        }
    }

    pub fn peek(&mut self) -> Result<Token<'a>> {
        if let Some(token) = self.ahead.clone() {
            Ok(token)
        } else {
            let token = self.next()?;
            self.ahead = Some(token.clone());
            Ok(token)
        }
    }

    fn decode_integer(&mut self) -> Result<Token<'a>> {
        let offset = self.offset;
        self.expect_one(b'i')?;
        let integer_arr = self.consume_while(|c| c != b'e');
        self.expect_one(b'e')?;
        let length = self.offset - offset;
        Ok(Token {
            offset,
            length,
            data: TokenData::Integer(integer_arr),
        })
    }

    fn decode_string(&mut self) -> Result<Token<'a>> {
        let offset = self.offset;
        let integer_arr = self.consume_while(|c| c != b':');
        self.expect_one(b':')?;
        let integer_str =
            std::str::from_utf8(integer_arr).map_err(|_| Error::new(ErrorKind::InvalidData))?;
        let string_len = integer_str
            .parse::<usize>()
            .map_err(|_| Error::new(ErrorKind::InvalidData))?;
        let string = self.consume_n(string_len)?;
        let length = self.offset - offset;
        Ok(Token {
            offset,
            length,
            data: TokenData::ByteString(string),
        })
    }

    fn peek_one(&self) -> Result<u8> {
        self.data
            .get(self.offset)
            .copied()
            .ok_or(Error::new(ErrorKind::EOF))
    }

    fn consume_one(&mut self) -> Result<u8> {
        let v = self.data.get(self.offset).copied();
        self.offset += 1;
        v.ok_or(Error::new(ErrorKind::EOF))
    }

    fn consume_n(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.offset.saturating_add(n) > self.data.len() {
            Err(Error::new(ErrorKind::UnexpectedEOF))
        } else {
            let v = &self.data[self.offset..self.offset + n];
            self.offset += n;
            Ok(v)
        }
    }

    fn consume_while<F>(&mut self, f: F) -> &'a [u8]
    where
        F: Fn(u8) -> bool,
    {
        let start = self.offset;
        while let Some(&c) = self.data.get(self.offset) {
            if !f(c) {
                break;
            }
            self.offset += 1;
        }
        &self.data[start..self.offset]
    }

    fn expect_one(&mut self, v: u8) -> Result<()> {
        match self.consume_one() {
            Ok(c) if c == v => Ok(()),
            Ok(_) => Err(Error::new(ErrorKind::InvalidData)),
            Err(e) if e.kind == ErrorKind::EOF => Err(Error::new(ErrorKind::UnexpectedEOF)),
            Err(e) => Err(e),
        }
    }
}

fn parse_integer(v: &[u8]) -> Result<i64> {
    let str = std::str::from_utf8(v).map_err(|_| Error::new(ErrorKind::InvalidData))?;
    str.parse::<i64>()
        .map_err(|_| Error::new(ErrorKind::InvalidData))
}

pub enum ValueData<'a> {
    Integer(i64),
    Bytes(&'a [u8]),
    List(Vec<Value<'a>>),
    Dict(Dict<'a>),
}

impl<'a> std::fmt::Debug for ValueData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::Bytes(arg0) => match std::str::from_utf8(arg0) {
                Ok(str) => f.write_str(str),
                _ => write!(f, "<{} bytes>", arg0.len()),
            },
            Self::List(arg0) => f.debug_tuple("List").field(arg0).finish(),
            Self::Dict(arg0) => f.debug_tuple("Dict").field(arg0).finish(),
        }
    }
}

impl<'a> ValueData<'a> {
    pub fn as_integer(&self) -> Result<i64> {
        match self {
            ValueData::Integer(v) => Ok(*v),
            _ => Err(Error::message("expected integer")),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            ValueData::Bytes(v) => Ok(*v),
            _ => Err(Error::message("expected byte string")),
        }
    }

    pub fn as_str(&self) -> Result<&str> {
        match self {
            ValueData::Bytes(v) => match std::str::from_utf8(v) {
                Ok(str) => Ok(str),
                _ => Err(Error::message("byte string contains invalid utf-8")),
            },
            _ => Err(Error::message("expected utf-8 byte string")),
        }
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        match self {
            ValueData::List(v) => Ok(v.as_slice()),
            _ => Err(Error::message("expected list")),
        }
    }

    pub fn as_dict(&self) -> Result<&Dict> {
        match self {
            ValueData::Dict(dict) => Ok(dict),
            _ => Err(Error::message("expected dictonary")),
        }
    }
}

pub struct Value<'a> {
    pub offset: usize,
    pub length: usize,
    pub bytes: &'a [u8],
    pub data: ValueData<'a>,
}

impl<'a> std::fmt::Debug for Value<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <ValueData<'a> as std::fmt::Debug>::fmt(&self.data, f)
    }
}

impl<'a> Value<'a> {
    pub fn as_integer(&self) -> Result<i64> {
        self.data.as_integer()
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        self.data.as_bytes()
    }

    pub fn as_str(&self) -> Result<&str> {
        self.data.as_str()
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        self.data.as_list()
    }

    pub fn as_dict(&self) -> Result<&Dict> {
        self.data.as_dict()
    }
}

struct DictEntry<'a> {
    key: &'a [u8],
    value: Value<'a>,
}

pub struct Dict<'a> {
    entries: Vec<DictEntry<'a>>,
}

impl<'a> std::fmt::Debug for Dict<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for entry in &self.entries {
            if let Ok(str) = std::str::from_utf8(&entry.key) {
                m.key(&str);
            } else {
                m.key(&entry.key);
            }
            m.value(&entry.value);
        }
        m.finish()
    }
}

impl<'a> Dict<'a> {
    pub fn find<T: FromValue>(&self, key: &[u8]) -> Result<Option<T>> {
        match self.find_value(key) {
            Some(value) => Some(
                T::from_value(value)
                    .with_context(|| format!("decoding key value: '{}'", TryDisplayUtf8(key))),
            )
            .transpose(),
            None => Ok(None),
        }
    }

    pub fn require<T: FromValue>(&self, key: &[u8]) -> Result<T> {
        let value = self.require_value(key)?;
        T::from_value(value)
            .with_context(|| format!("decoding key value: '{}'", TryDisplayUtf8(key)))
    }

    pub fn find_value(&self, key: &[u8]) -> Option<&Value<'a>> {
        for entry in &self.entries {
            if entry.key == key {
                return Some(&entry.value);
            }
        }
        None
    }

    pub fn require_value(&self, key: &[u8]) -> Result<&Value<'a>> {
        self.find_value(key)
            .ok_or(Error::new(ErrorKind::MissingKey))
            .with_context(|| format!("fetching key: '{}'", TryDisplayUtf8(key)))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub fn decode<T: FromValue>(buf: &[u8]) -> Result<T> {
    let value = decode_value(buf)?;
    T::from_value(&value)
}

pub fn decode_value(buf: &[u8]) -> Result<Value> {
    fn decode_ext<'a>(buf: &'a [u8], tokenizer: &mut Tokenizer<'a>) -> Result<Value<'a>> {
        let token = match tokenizer.next() {
            Ok(token) => token,
            Err(e) if e.kind == ErrorKind::EOF => return Err(Error::new(ErrorKind::UnexpectedEOF)),
            Err(e) => return Err(e),
        };

        match token.data {
            TokenData::Integer(v) => {
                return Ok(Value {
                    offset: token.offset,
                    length: token.length,
                    bytes: &buf[token.offset..token.offset + token.length],
                    data: parse_integer(v).map(ValueData::Integer)?,
                })
            }
            TokenData::ByteString(v) => {
                return Ok(Value {
                    offset: token.offset,
                    length: token.length,
                    bytes: &buf[token.offset..token.offset + token.length],
                    data: ValueData::Bytes(v),
                })
            }
            TokenData::ListBegin => {
                let offset = token.offset;
                let mut values = Vec::new();
                loop {
                    let peek = tokenizer.peek()?;
                    if peek.data == TokenData::End {
                        let end_token = tokenizer.next()?;
                        let length = end_token.offset - offset + end_token.length;
                        return Ok(Value {
                            offset,
                            length,
                            bytes: &buf[offset..offset + length],
                            data: ValueData::List(values),
                        });
                    }
                    values.push(decode_ext(buf, tokenizer)?);
                }
            }
            TokenData::DictBegin => {
                let offset = token.offset;
                let mut entries = Vec::new();
                loop {
                    let peek = tokenizer.peek()?;
                    if peek.data == TokenData::End {
                        let end_token = tokenizer.next()?;
                        let length = end_token.offset - offset + end_token.length;
                        return Ok(Value {
                            offset,
                            length,
                            bytes: &buf[offset..offset + length],
                            data: ValueData::Dict(Dict { entries }),
                        });
                    }

                    let key = match decode_ext(buf, tokenizer)?.data {
                        ValueData::Bytes(v) => v,
                        _ => return Err(Error::message("dictionary key must be a binary string")),
                    };
                    let value = decode_ext(buf, tokenizer)?;
                    entries.push(DictEntry { key, value });
                }
            }
            TokenData::End => return Err(Error::message("unexpected end token")),
        }
    }

    let mut tokenizer = Tokenizer::new(buf);
    decode_ext(buf, &mut tokenizer)
}

pub trait FromValue: Sized {
    fn from_value(value: &Value) -> Result<Self>;
}

impl FromValue for String {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(value.as_str()?.to_owned())
    }
}

impl FromValue for u32 {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(value.as_integer()? as u32)
    }
}

impl FromValue for u64 {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(value.as_integer()? as u64)
    }
}

impl<T> FromValue for Vec<T>
where
    T: FromValue,
{
    fn from_value(value: &Value) -> Result<Self> {
        let list = value.as_list()?;
        let mut values = Vec::with_capacity(list.len());
        for v in list {
            values.push(T::from_value(v)?);
        }
        Ok(values)
    }
}
