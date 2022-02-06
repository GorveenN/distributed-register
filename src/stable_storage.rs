use crate::StableStorage;
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use std::{fs::OpenOptions, io::Read, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

fn base64_encode_pathsafe<T>(input: T) -> String
where
    T: AsRef<[u8]>,
{
    base64::encode(input).replace("/", "_")
}

pub(crate) struct StableStorageImpl {
    root: PathBuf,
    keys: HashSet<Vec<u8>>,
}

impl StableStorageImpl {
    const STATE_FILE: &'static str = ".StableStorage";
    // const TEMP_DIR: &'static str = "temp";
    // const FILES_DIR: &'static str = "files";
    const KEY_SIZE: usize = 64;

    pub(crate) fn new(root: PathBuf) -> Self {
        // create_dir_all(root.join(Self::TEMP_DIR)).unwrap();
        // create_dir_all(root.join(Self::FILES_DIR)).unwrap();

        let keys = match OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(root.join(Self::STATE_FILE))
        {
            Ok(mut x) => {
                let mut buf = Vec::new();
                x.read_to_end(&mut buf).unwrap();

                buf.chunks(Self::KEY_SIZE)
                    .filter(|a| a.len() == Self::KEY_SIZE)
                    .map(|c| c.to_vec())
                    .collect()
            }
            // TODO delete old files
            Err(e) => {
                panic!(
                    "Error restoring StableStorage from {} file: {}",
                    Self::STATE_FILE,
                    e
                )
            }
        };

        for path in std::fs::read_dir(root.clone()).unwrap() {
            let abs_path = path.as_ref().unwrap().path();
            if let Some(file_name) = abs_path.file_name() {
                let file_name = file_name.to_str().unwrap();
                if file_name.ends_with(".tmp") {
                    std::fs::remove_file(abs_path).unwrap();
                }
            }
        }

        Self { root, keys }
    }

    fn key_to_path<T>(key: T) -> String
    where
        T: AsRef<[u8]>,
    {
        base64_encode_pathsafe(key)
    }
}

fn sha256<T>(data: T) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    let mut hasher = Sha512::new();
    hasher.update(data);
    let key_hashed = hasher.finalize();

    key_hashed.into_iter().collect::<Vec<u8>>()
}

#[async_trait::async_trait]
impl StableStorage for StableStorageImpl {
    async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        if key.len() > 255 {
            return Err(String::from("key should be at most 255 characters long"));
        }

        if value.len() > 65535 {
            return Err(String::from("values should be at most 65535 bytes long"));
        }

        let tmpfile_path = self.root.join(Uuid::new_v4().to_string() + ".tmp");
        let mut tmpfile = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmpfile_path)
            .await
            .expect("Could not create temp file");

        tmpfile
            .write_all(value)
            .await
            .expect("Could write to temp file");

        tmpfile
            .sync_data()
            .await
            .expect("Sync data on tmp file failed");

        let key_hashed = sha256(key);
        assert!(key_hashed.len() == Self::KEY_SIZE);
        let filename = Self::key_to_path(&key_hashed);

        tokio::fs::rename(tmpfile_path, self.root.join(filename))
            .await
            .expect("Couldn't move file to new location.");

        tmpfile
            .sync_data()
            .await
            .expect("Sync data on moved file failed");

        if !self.keys.contains(&key_hashed) {
            let mut file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(self.root.join(Self::STATE_FILE))
                .await
                .expect("Could not open config file.");

            file.write_all(&key_hashed)
                .await
                .unwrap_or_else(|_| panic!("Could not write key: {}", key));

            file.sync_data()
                .await
                .expect("Could not sync recovery data.");

            self.keys.insert(key_hashed);
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let key_hashed = sha256(key);
        match self.keys.get(&key_hashed) {
            Some(_) => {
                let filename = Self::key_to_path(key_hashed);
                let mut file = tokio::fs::File::open(self.root.join(filename))
                    .await
                    .unwrap();
                let mut contents = vec![];
                file.read_to_end(&mut contents).await.unwrap();
                Some(contents)
            }
            None => None,
        }
    }
}
