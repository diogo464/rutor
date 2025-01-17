use crate::Sha1;

const DEFAULT_PIECE_LENGTH: u32 = 4096;

#[derive(Debug, Default, Clone)]
pub struct TorrentCreatorConfig {
    pub name: Option<String>,
    pub announce: Option<String>,
    pub announce_list: Option<Vec<Vec<String>>>,
    pub creator: Option<String>,
    pub comment: Option<String>,
    pub piece_length: Option<u32>,
}

pub struct TorrentCreatorFile<'a> {
    creator: &'a mut TorrentCreator,
    path: String,
    length: u64,
}

impl<'a> TorrentCreatorFile<'a> {
    pub fn push_data(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        self.creator.push_data(data);
    }

    pub fn finish(self) {}
}

impl<'a> Drop for TorrentCreatorFile<'a> {
    fn drop(&mut self) {
        self.creator.files.push(FileEntry {
            path: std::mem::take(&mut self.path),
            length: self.length,
        });
    }
}

#[derive(Debug)]
struct FileEntry {
    path: String,
    length: u64,
}

#[derive(Debug)]
pub struct TorrentCreator {
    config: TorrentCreatorConfig,
    piece_length: u32,
    pieces: Vec<Sha1>,
    files: Vec<FileEntry>,
    buffer: Vec<u8>,
}

impl TorrentCreator {
    pub fn new(config: TorrentCreatorConfig) -> Self {
        let piece_length = config.piece_length.unwrap_or(DEFAULT_PIECE_LENGTH);
        Self {
            config,
            piece_length,
            pieces: Default::default(),
            files: Default::default(),
            buffer: Default::default(),
        }
    }

    fn push_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);

        let piece_length = self.piece_length as usize;
        while self.buffer.len() > piece_length {
            let piece = &self.buffer[0..piece_length];
            let piece_hash = Sha1::hash(piece);
            self.buffer.drain(0..piece_length);
            self.pieces.push(piece_hash);
        }
    }

    pub fn file<'a>(&'a mut self, path: &str) -> TorrentCreatorFile<'a> {
        TorrentCreatorFile {
            creator: self,
            path: path.to_string(),
            length: 0,
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if !self.buffer.is_empty() {
            assert!(self.buffer.len() < self.piece_length as usize);
            let piece = self.buffer.as_slice();
            let piece_hash = Sha1::hash(piece);
            self.pieces.push(piece_hash);
        }

        let announce = self.config.announce.unwrap_or_default();
        let name = self.config.name.unwrap_or_default();
        let files = self.files;
        println!("{:?}", files);
        let pieces = {
            let mut pieces = Vec::with_capacity(self.pieces.len() * 20);
            for piece in &self.pieces {
                pieces.extend_from_slice(&piece.0);
            }
            pieces
        };

        bencode::encode_fn(|encoder| {
            let mut dict = encoder.dict();
            dict.push(b"announce", &announce);
            dict.push_with_encoder(b"info", |encoder| {
                let mut info = encoder.dict();
                info.push(b"name", &name);
                info.push(b"piece length", &self.piece_length);
                info.push_with_encoder(b"pieces", |encoder| encoder.string(&pieces));
                match files.len() {
                    0 => info.push(b"length", 0u32),
                    1 => info.push(b"length", &files[0].length),
                    _ => {
                        info.push_with_encoder(b"files", |encoder| {
                            let mut files_list = encoder.list();
                            for file in &files {
                                files_list.push_with_encoder(|encoder| {
                                    let mut file_dict = encoder.dict();
                                    file_dict.push(b"length", &file.length);
                                    file_dict.push(b"path", &file.path);
                                });
                            }
                        });
                    }
                }
            });
        })
    }
}

#[cfg(test)]
mod test {
    use crate::TorrentInfo;

    use super::*;

    #[test]
    fn single_file() {
        let config = TorrentCreatorConfig {
            name: Some("name".to_string()),
            announce: Some("announce".to_string()),
            ..Default::default()
        };
        let mut creator = TorrentCreator::new(config);
        let mut file = creator.file("hello.txt");
        file.push_data(b"hello world");
        file.finish();
        let content = creator.finish();
        println!("{:?}", content);

        let info = TorrentInfo::decode(&content).unwrap();
        println!("{:?}", info);

        assert_eq!(info.name(), "name");
        assert_eq!(info.announce(), "announce");
        assert_eq!(info.total_size(), 11);
        assert_eq!(info.files().len(), 1);
        assert_eq!(info.files()[0].path().to_str().unwrap(), "name");
        assert_eq!(info.files()[0].length(), 11);
    }

    #[test]
    fn multiple_file() {
        let config = TorrentCreatorConfig {
            name: Some("name".to_string()),
            announce: Some("announce".to_string()),
            ..Default::default()
        };
        let mut creator = TorrentCreator::new(config);
        let mut file = creator.file("hello.txt");
        file.push_data(b"hello world");
        file.finish();
        let mut file = creator.file("world.txt");
        file.push_data(b"world hello");
        file.finish();
        let content = creator.finish();

        let info = TorrentInfo::decode(&content).unwrap();
        println!("{:?}", info);

        assert_eq!(info.name(), "name");
        assert_eq!(info.announce(), "announce");
        assert_eq!(info.total_size(), 22);
        assert_eq!(info.files().len(), 2);
        assert_eq!(info.files()[0].path().to_str().unwrap(), "hello.txt");
        assert_eq!(info.files()[0].length(), 11);
        assert_eq!(info.files()[1].path().to_str().unwrap(), "world.txt");
        assert_eq!(info.files()[1].length(), 11);
    }
}
