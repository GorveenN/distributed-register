use crate::sectors_manager_public::SectorsManager;
use crate::{SectorIdx, SectorVec, ATOMIC_REGISTER_INSTANCES_COUNT};
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

// we should run the same number of mutexes as atomic registers. By doing so we could achieve lock
// free SectorManager, since AtomicRegister can run handle single message at a time
const MUTEX_POOL_SIZE: usize = ATOMIC_REGISTER_INSTANCES_COUNT;

#[derive(Clone, Debug)]
struct SectorMetadata {
    idx: SectorIdx,
    timestamp: u64,
    write_rank: u8,
}

impl SectorMetadata {
    fn from_filename(filename: &str) -> Option<Self> {
        let parts: Vec<_> = filename.split('_').collect();

        match parts[..] {
            [idx_raw, timestamp_raw, write_rank_raw] => {
                let idx: SectorIdx = idx_raw.parse().ok()?;
                let timestamp: u64 = timestamp_raw.parse().ok()?;
                let write_rank: u8 = write_rank_raw.parse().ok()?;
                Some(SectorMetadata {
                    idx,
                    timestamp,
                    write_rank,
                })
            }
            _ => None,
        }
    }

    fn filename(&self) -> String {
        format!("{}_{}_{}", self.idx, self.timestamp, self.write_rank)
    }

    async fn try_read_data(&self, root: &Path) -> Result<SectorVec, Box<dyn Error>> {
        let filename = root.join(self.filename());

        let data = match tokio::fs::File::open(&filename).await {
            Ok(mut file) => {
                let mut buf = vec![0u8; 4096];
                file.read_exact(&mut buf).await.unwrap();
                buf
            }
            Err(err) => panic!(
                "Could not open file for sector: {}, path: {:?}, {}",
                self.idx, filename, err
            ),
        };

        Ok(SectorVec(data))
    }
}

type SectorMap = HashMap<SectorIdx, SectorMetadata>;

pub struct SectorsManagerImpl {
    path: PathBuf,
    hashmaps: Vec<Mutex<SectorMap>>,
}

impl SectorsManagerImpl {
    pub fn new(path: PathBuf) -> Self {
        let hashmaps = Self::restore_hashmaps(&path);
        Self { path, hashmaps }
    }

    fn restore_hashmaps(path: &Path) -> Vec<Mutex<SectorMap>> {
        let mut sector_to_metadata = HashMap::new();
        let dir = std::fs::read_dir(&path).unwrap();
        for child in dir {
            // while let Some(child) = dir.next_entry().unwrap() {
            let path = child.unwrap().path();
            if path.extension().is_some() {
                // tmp file
                std::fs::remove_file(path).unwrap();
            } else if let Some(filename) = path.file_name() {
                if let Some(metadata) = SectorMetadata::from_filename(filename.to_str().unwrap()) {
                    sector_to_metadata
                        .entry(metadata.idx)
                        .or_insert_with(Vec::new)
                        .push(metadata);
                }
            }
        }

        let mut final_maps: Vec<SectorMap> = (0..MUTEX_POOL_SIZE).map(|_| HashMap::new()).collect();
        for mut metadatas in sector_to_metadata.into_values() {
            metadatas.sort_by(|a, b| {
                a.timestamp
                    .cmp(&b.timestamp)
                    .then(a.write_rank.cmp(&b.write_rank))
            });
            let latest_metadata = metadatas.last().unwrap().clone();

            final_maps[latest_metadata.idx as usize % MUTEX_POOL_SIZE]
                .insert(latest_metadata.idx, latest_metadata);

            for old_metadata in metadatas[..metadatas.len() - 1].iter() {
                std::fs::remove_file(path.join(old_metadata.filename())).unwrap();
            }
        }

        final_maps.into_iter().map(Mutex::new).collect()
    }

    fn get_hashmap(&self, idx: SectorIdx) -> &Mutex<SectorMap> {
        &self.hashmaps[idx as usize % MUTEX_POOL_SIZE]
    }
}

#[async_trait::async_trait]
impl SectorsManager for SectorsManagerImpl {
    async fn read_data(&self, idx: SectorIdx) -> SectorVec {
        match self.get_hashmap(idx).lock().await.get(&idx) {
            Some(metadata) => metadata
                .try_read_data(&self.path)
                .await
                .unwrap_or_else(|_| SectorVec(vec![0; 4096])),
            None => SectorVec(vec![0; 4096]),
        }
    }

    async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8) {
        let hashmap = self.get_hashmap(idx).lock().await;

        hashmap
            .get(&idx)
            .map(|metadata| (metadata.timestamp, metadata.write_rank))
            .unwrap_or((0, 0))
    }

    async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) {
        let mut hashmap = self.get_hashmap(idx).lock().await;

        let new_metadata = SectorMetadata {
            idx,
            timestamp: sector.1,
            write_rank: sector.2,
        };

        let chunk_path = self.path.join(new_metadata.filename());
        let chunk_path_tmp = chunk_path.with_extension("tmp");
        {
            match OpenOptions::new()
                .create(true)
                .write(true)
                .open(&chunk_path_tmp)
                .await
            {
                Ok(mut tmp_file) => {
                    tmp_file
                        .write_all(&sector.0 .0)
                        .await
                        .expect("Could not write tmp file");
                    tmp_file.sync_data().await.unwrap();
                    tokio::fs::rename(chunk_path_tmp, &chunk_path)
                        .await
                        .unwrap();
                    if let Some(metadata) = hashmap.get(&idx) {
                        let old_chunk_filename = self.path.join(metadata.filename());
                        tokio::fs::remove_file(old_chunk_filename)
                            .await
                            .expect("Could not remove old file");
                    }
                    hashmap.insert(idx, new_metadata);
                }
                _ => panic!("Could not create tmp sector file"),
            };
        }
    }
}
