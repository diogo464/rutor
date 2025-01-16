#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub sort_dict: bool,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self { sort_dict: true }
    }
}

#[derive(Debug)]
pub struct Encoder<'a> {
    config: &'a EncoderConfig,
    buf: &'a mut Vec<u8>,
}

pub struct ListEncoder<'e, 'a> {
    encoder: &'e mut Encoder<'a>,
}

impl<'e, 'a> Drop for ListEncoder<'e, 'a> {
    fn drop(&mut self) {
        self.encoder.buf.push(b'e');
    }
}

impl<'e, 'a> ListEncoder<'e, 'a> {
    pub fn push<T: Encode>(&mut self, value: T) {
        value.encode(self.encoder);
    }

    pub fn push_with_encoder(&mut self, f: impl FnOnce(&mut Encoder)) {
        f(self.encoder);
    }
}

pub struct DictEncoder<'e, 'a> {
    encoder: &'e mut Encoder<'a>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'e, 'a> Drop for DictEncoder<'e, 'a> {
    fn drop(&mut self) {
        self.pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for pair in &self.pairs {
            self.encoder.string(&pair.0);
            self.encoder.buf.extend_from_slice(&pair.1);
        }
        self.encoder.buf.push(b'e');
    }
}

impl<'e, 'a> DictEncoder<'e, 'a> {
    pub fn push<T: Encode>(&mut self, key: impl AsRef<[u8]>, value: T) {
        if self.encoder.config.sort_dict {
            let key = key.as_ref().to_vec();
            let value = encode_with(self.encoder.config, value);
            self.pairs.push((key, value));
        } else {
            self.encoder.string(key.as_ref());
            value.encode(self.encoder);
        }
    }

    pub fn push_with_encoder(&mut self, key: impl AsRef<[u8]>, f: impl FnOnce(&mut Encoder)) {
        if self.encoder.config.sort_dict {
            let key = key.as_ref().to_vec();
            let mut buf = Vec::new();
            {
                let mut encoder = Encoder {
                    config: self.encoder.config,
                    buf: &mut buf,
                };
                f(&mut encoder);
            }
            self.pairs.push((key, buf));
        } else {
            self.encoder.string(key.as_ref());
            f(self.encoder);
        }
    }
}

impl<'a> Encoder<'a> {
    pub fn new(buf: &'a mut Vec<u8>, config: &'a EncoderConfig) -> Self {
        Self { buf, config }
    }

    pub fn integer(&mut self, value: i64) {
        self.buf.push(b'i');
        self.buf.extend_from_slice(value.to_string().as_bytes());
        self.buf.push(b'e');
    }

    pub fn string(&mut self, value: &[u8]) {
        self.buf
            .extend_from_slice(value.len().to_string().as_bytes());
        self.buf.push(b':');
        self.buf.extend_from_slice(value);
    }

    pub fn list<'e>(&'e mut self) -> ListEncoder<'e, 'a> {
        self.buf.push(b'l');
        ListEncoder { encoder: self }
    }

    pub fn dict<'e>(&'e mut self) -> DictEncoder<'e, 'a> {
        self.buf.push(b'd');
        DictEncoder {
            encoder: self,
            pairs: Default::default(),
        }
    }
}

pub trait Encode {
    fn encode(&self, encoder: &mut Encoder);
}

pub fn encode_with<T: Encode>(config: &EncoderConfig, value: T) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut encoder = Encoder {
            config,
            buf: &mut buf,
        };
        value.encode(&mut encoder);
    }
    buf
}

pub fn encode<T: Encode>(value: T) -> Vec<u8> {
    encode_with(&EncoderConfig::default(), value)
}

macro_rules! impl_encode_for_integer {
    ($t:ty) => {
        impl Encode for $t {
            fn encode(&self, encoder: &mut Encoder) {
                encoder.integer(*self as i64);
            }
        }
    };
}
impl_encode_for_integer!(i8);
impl_encode_for_integer!(i16);
impl_encode_for_integer!(i32);
impl_encode_for_integer!(i64);
impl_encode_for_integer!(u8);
impl_encode_for_integer!(u16);
impl_encode_for_integer!(u32);
impl_encode_for_integer!(u64);

impl Encode for &str {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.string(self.as_bytes());
    }
}

impl Encode for String {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.string(self.as_bytes());
    }
}

impl<T: Encode> Encode for &T {
    fn encode(&self, encoder: &mut Encoder) {
        (*self).encode(encoder);
    }
}

impl<T: Encode> Encode for &[T] {
    fn encode(&self, encoder: &mut Encoder) {
        let mut list = encoder.list();
        for value in *self {
            list.push(value);
        }
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, encoder: &mut Encoder) {
        let mut list = encoder.list();
        for value in self {
            list.push(value);
        }
    }
}

impl<K: AsRef<[u8]>, V: Encode> Encode for std::collections::BTreeMap<K, V> {
    fn encode(&self, encoder: &mut Encoder) {
        let mut dict = encoder.dict();
        for (key, value) in self {
            dict.push(key, value);
        }
    }
}

impl<K: AsRef<[u8]>, V: Encode> Encode for std::collections::HashMap<K, V> {
    fn encode(&self, encoder: &mut Encoder) {
        let mut dict = encoder.dict();
        for (key, value) in self {
            dict.push(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create predictable byte arrays
    fn make_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_integers() {
        // Basic integer tests
        assert_eq!(encode(0i64), b"i0e");
        assert_eq!(encode(42i64), b"i42e");
        assert_eq!(encode(-42i64), b"i-42e");
        assert_eq!(encode(i64::MAX), b"i9223372036854775807e");
        assert_eq!(encode(i64::MIN), b"i-9223372036854775808e");
    }

    #[test]
    fn test_strings() {
        // Using direct string encoding
        let mut buf = Vec::new();
        let config = EncoderConfig::default();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            encoder.string(b"");
        }
        assert_eq!(buf, b"0:");

        // Using &str with encode
        assert_eq!(encode("spam"), b"4:spam");
        assert_eq!(encode("hello:world"), b"11:hello:world");

        // Long string
        let long_bytes = make_bytes(1000);
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            encoder.string(&long_bytes);
        }
        let mut expected = format!("1000:").into_bytes();
        expected.extend_from_slice(&long_bytes);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_byte_slices_as_lists() {
        // Empty byte slice becomes an empty list
        assert_eq!(encode(b"" as &[u8]), b"le");

        // Byte slice becomes a list of integers
        assert_eq!(encode(b"abc" as &[u8]), b"li97ei98ei99ee");

        // Vec<u8> also becomes a list of integers
        assert_eq!(encode(vec![1u8, 2, 3]), b"li1ei2ei3ee");
    }

    #[test]
    fn test_lists() {
        // Empty list
        assert_eq!(encode(Vec::<i64>::new()), b"le");

        // List of integers
        let nums = vec![1i64, 2, 3];
        assert_eq!(encode(&nums), b"li1ei2ei3ee");

        // List of strings
        assert_eq!(encode(vec!["spam", "eggs"]), b"l4:spam4:eggse");

        // Mixed list using manual encoder
        let mut buf = Vec::new();
        let config = EncoderConfig::default();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut list = encoder.list();
            list.push(42i64);
            list.push_with_encoder(|e| {
                e.string(b"spam");
            });
            list.push_with_encoder(|e| {
                let mut l = e.list();
                l.push(1i64);
                l.push(2i64);
            });
        }
        assert_eq!(buf, b"li42e4:spamli1ei2eee");
    }

    #[test]
    fn test_dicts() {
        // Empty dict
        let mut buf = Vec::new();
        let config = EncoderConfig::default();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let _dict = encoder.dict();
        }
        assert_eq!(buf, b"de");

        // Simple dict
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();
            dict.push(b"cow", "moo");
            dict.push(b"spam", "eggs");
        }
        assert_eq!(buf, b"d3:cow3:moo4:spam4:eggse");

        // Dict with mixed types
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();
            dict.push(b"int", 42i64);
            dict.push(b"list", vec![1i64, 2, 3]);
            dict.push_with_encoder(b"dict", |e| {
                let mut d = e.dict();
                d.push(b"x", "y");
            });
        }
        assert_eq!(buf, b"d4:dictd1:x1:ye3:inti42e4:listli1ei2ei3eee");
    }

    #[test]
    fn test_dict_sorting() {
        // Test with sorting enabled (default)
        let mut buf = Vec::new();
        let config = EncoderConfig { sort_dict: true };
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();
            dict.push(b"z", 1i64);
            dict.push(b"a", 2i64);
            dict.push(b"m", 3i64);
        }
        assert_eq!(buf, b"d1:ai2e1:mi3e1:zi1ee");

        // Test with sorting disabled
        let mut buf = Vec::new();
        let config = EncoderConfig { sort_dict: false };
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();
            dict.push(b"z", 1i64);
            dict.push(b"a", 2i64);
            dict.push(b"m", 3i64);
        }
        assert_eq!(buf, b"d1:zi1e1:ai2e1:mi3ee");
    }

    #[test]
    fn test_nested_structures() {
        // Complex nested structure
        let mut buf = Vec::new();
        let config = EncoderConfig::default();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();

            // Add a nested list
            dict.push_with_encoder(b"list", |e| {
                let mut list = e.list();
                list.push(1i64);
                list.push_with_encoder(|e| {
                    let mut l = e.list();
                    l.push(2i64);
                    l.push(3i64);
                });
                list.push(4i64);
            });

            // Add a nested dict
            dict.push_with_encoder(b"dict", |e| {
                let mut d = e.dict();
                d.push(b"key1", "value1");
                d.push_with_encoder(b"key2", |e| {
                    let mut d2 = e.dict();
                    d2.push(b"inner", "value2");
                });
            });
        }
        assert_eq!(
            buf,
            b"d4:dictd4:key16:value14:key2d5:inner6:value2ee4:listli1eli2ei3eei4eee"
        );
    }

    #[test]
    fn test_custom_encode_implementation() {
        // Example struct implementing Encode
        #[derive(Debug)]
        struct Person {
            name: String,
            age: i64,
            hobbies: Vec<String>,
        }

        impl Encode for Person {
            fn encode(&self, encoder: &mut Encoder) {
                let mut dict = encoder.dict();
                dict.push(b"name", &self.name);
                dict.push(b"age", self.age);
                dict.push_with_encoder(b"hobbies", |e| {
                    let mut list = e.list();
                    for hobby in &self.hobbies {
                        list.push(hobby);
                    }
                });
            }
        }

        let person = Person {
            name: "Alice".to_string(),
            age: 30,
            hobbies: vec!["reading".to_string(), "coding".to_string()],
        };

        assert_eq!(
            encode(person),
            b"d3:agei30e7:hobbiesl7:reading6:codinge4:name5:Alicee"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Empty string using string method
        let mut buf = Vec::new();
        let config = EncoderConfig::default();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            encoder.string(b"");
        }
        assert_eq!(buf, b"0:");

        // Very long string
        let long_bytes = make_bytes(65536);
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            encoder.string(&long_bytes);
        }
        let mut expected = format!("65536:").into_bytes();
        expected.extend_from_slice(&long_bytes);
        assert_eq!(buf, expected);

        // Empty containers
        assert_eq!(encode(Vec::<i64>::new()), b"le");
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let _dict = encoder.dict();
        }
        assert_eq!(buf, b"de");

        // Dict with empty string key
        let mut buf = Vec::new();
        {
            let mut encoder = Encoder::new(&mut buf, &config);
            let mut dict = encoder.dict();
            dict.push(b"", "empty key");
        }
        assert_eq!(buf, b"d0:9:empty keye");
    }
}
