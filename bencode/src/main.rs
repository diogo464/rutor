use bencode::{Error, FromValue, Result, Value};

struct Sha1([u8; 20]);

impl std::fmt::Debug for Sha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha1(")?;
        for v in self.0 {
            write!(f, "{:x}", v)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

#[derive(Debug)]
struct Metainfo {
    announce: String,
    info: Info,
}

#[derive(Debug)]
struct InfoFile {
    path: String,
    length: u64,
}

#[derive(Debug)]
struct Info {
    name: String,
    piece_length: u64,
    pieces: Vec<Sha1>,
    files: Vec<InfoFile>,
}

impl FromValue for InfoFile {
    fn from_value(value: &Value) -> Result<Self> {
        let dict = value.as_dict()?;
        let path = dict.require::<Vec<String>>(b"path")?.join("/");
        Ok(Self {
            length: dict.require(b"length")?,
            path,
        })
    }
}

impl FromValue for Info {
    fn from_value(value: &Value) -> Result<Self> {
        let dict = value.as_dict()?;
        let name = dict.require::<String>(b"name")?;
        let piece_length = dict.require(b"piece length")?;
        let pieces_bytes = dict.require_value(b"pieces")?.as_bytes()?;
        if pieces_bytes.len() % 20 != 0 {
            return Err(Error::message(
                "size of pieces byte string is not a multiple of 20",
            ));
        }

        let mut pieces = Vec::with_capacity(pieces_bytes.len() / 20);
        for i in 0..pieces_bytes.len() / 20 {
            let hash = &pieces_bytes[i * 20..(i + 1) * 20];
            pieces.push(Sha1(TryFrom::try_from(hash).unwrap()));
        }

        let mut files = Vec::new();
        let mut length = 0;
        let length_value = dict.find_value(b"length");
        let files_value = dict.find_value(b"files");
        match (length_value, files_value) {
            (Some(l), None) => match l {
                Value::Integer(l) => {
                    length = *l as u64;
                    files.push(InfoFile {
                        path: name.clone(),
                        length,
                    })
                }
                _ => return Err(Error::message("length field must be an integer")),
            },
            (None, Some(f)) => match f {
                Value::List(f) => {
                    for v in f {
                        let file = InfoFile::from_value(v)?;
                        length += file.length;
                        files.push(file);
                    }
                }
                _ => return Err(Error::message("files field must be a list")),
            },
            (Some(_), Some(_)) => {
                return Err(Error::message(
                    "info dictionary cannot contain both files and length field",
                ))
            }
            (None, None) => {
                return Err(Error::message(
                    "info dictionary must contain either files or length field",
                ))
            }
        }

        Ok(Self {
            name,
            piece_length,
            pieces,
            files,
        })
    }
}

impl FromValue for Metainfo {
    fn from_value(value: &Value) -> Result<Self> {
        let dict = value.as_dict()?;
        let announce = dict.require(b"announce")?;
        let info = dict.require(b"info")?;
        Ok(Self { announce, info })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read("hungergames.torrent").unwrap();
    let metainfo = bencode::decode::<Metainfo>(&content).unwrap();
    println!("{:#?}", metainfo);
    Ok(())
}
