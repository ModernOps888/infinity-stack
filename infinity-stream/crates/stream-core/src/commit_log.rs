use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{LogRecord, NewRecord};

#[derive(Debug, Clone)]
struct OffsetPos {
    segment: PathBuf,
    pos: u64,
}

#[derive(Debug, Default)]
struct PartitionLog {
    next_offset: u64,
    current_base: u64,
    current_size: u64,
    index: HashMap<u64, OffsetPos>,
}

#[derive(Debug)]
pub struct CommitLog {
    root: PathBuf,
    segment_max_bytes: u64,
    partitions: HashMap<(String, u32), PartitionLog>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRecord {
    offset: u64,
    key: Option<String>,
    value: serde_json::Value,
    timestamp: String,
}

impl CommitLog {
    /// Reject topic names that could escape the log root (defense-in-depth;
    /// the API layer also validates, but never trust a name at the FS sink).
    fn ensure_safe_topic(topic: &str) -> Result<()> {
        let safe = !topic.is_empty()
            && topic.len() <= 128
            && topic
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if safe {
            Ok(())
        } else {
            Err(CoreError::Invalid(format!("unsafe topic name: {topic:?}")))
        }
    }

    pub fn open(data_dir: impl AsRef<Path>, segment_max_bytes: u64) -> Result<Self> {
        let root = data_dir.as_ref().join("logs");
        fs::create_dir_all(&root)?;
        let mut me = Self {
            root,
            segment_max_bytes: segment_max_bytes.max(256),
            partitions: HashMap::new(),
        };
        me.recover()?;
        Ok(me)
    }

    pub fn create_partition(&mut self, topic: &str, partition: u32) -> Result<()> {
        Self::ensure_safe_topic(topic)?;
        fs::create_dir_all(self.partition_dir(topic, partition))?;
        self.partitions
            .entry((topic.to_string(), partition))
            .or_default();
        Ok(())
    }

    pub fn delete_topic(&mut self, topic: &str) -> Result<()> {
        Self::ensure_safe_topic(topic)?;
        let dir = self.root.join(topic);
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        self.partitions.retain(|(t, _), _| t != topic);
        Ok(())
    }

    pub fn append(
        &mut self,
        topic: &str,
        partition: u32,
        records: Vec<NewRecord>,
    ) -> Result<Vec<LogRecord>> {
        self.create_partition(topic, partition)?;
        let key = (topic.to_string(), partition);
        let dir = self.partition_dir(topic, partition);
        let part = self.partitions.get_mut(&key).expect("created");
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let offset = part.next_offset;
            let stored = StoredRecord {
                offset,
                key: rec.key,
                value: rec.value,
                timestamp: Utc::now().to_rfc3339(),
            };
            let line = serde_json::to_vec(&stored)?;
            let needed = line.len() as u64 + 1;
            if part.current_size > 0 && part.current_size + needed > self.segment_max_bytes {
                part.current_base = offset;
                part.current_size = 0;
            }
            let path = dir.join(format!("{:020}.log", part.current_base));
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&path)?;
            let pos = file.seek(SeekFrom::End(0))?;
            file.write_all(&line)?;
            file.write_all(b"\n")?;
            file.flush()?;
            part.index.insert(offset, OffsetPos { segment: path, pos });
            part.current_size += needed;
            part.next_offset += 1;
            out.push(LogRecord {
                topic: topic.to_string(),
                partition,
                offset,
                key: stored.key,
                value: stored.value,
                timestamp: stored.timestamp,
            });
        }
        Ok(out)
    }

    pub fn read_from(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<LogRecord>> {
        Self::ensure_safe_topic(topic)?;
        let Some(part) = self.partitions.get(&(topic.to_string(), partition)) else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        let mut cur = offset;
        while out.len() < max {
            let Some(pos) = part.index.get(&cur) else {
                break;
            };
            let file = File::open(&pos.segment)?;
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(pos.pos))?;
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let stored: StoredRecord = serde_json::from_str(line.trim_end())?;
            out.push(LogRecord {
                topic: topic.to_string(),
                partition,
                offset: stored.offset,
                key: stored.key,
                value: stored.value,
                timestamp: stored.timestamp,
            });
            cur += 1;
        }
        Ok(out)
    }

    pub fn next_offset(&self, topic: &str, partition: u32) -> u64 {
        self.partitions
            .get(&(topic.to_string(), partition))
            .map(|p| p.next_offset)
            .unwrap_or(0)
    }

    pub fn total_records(&self) -> u64 {
        self.partitions.values().map(|p| p.next_offset).sum()
    }

    fn recover(&mut self) -> Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        for topic_entry in fs::read_dir(&self.root)? {
            let topic_entry = topic_entry?;
            if !topic_entry.file_type()?.is_dir() {
                continue;
            }
            let topic = topic_entry.file_name().to_string_lossy().to_string();
            for part_entry in fs::read_dir(topic_entry.path())? {
                let part_entry = part_entry?;
                if !part_entry.file_type()?.is_dir() {
                    continue;
                }
                let partition: u32 = part_entry
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .unwrap_or(0);
                self.recover_partition(&topic, partition, &part_entry.path())?;
            }
        }
        Ok(())
    }

    fn recover_partition(&mut self, topic: &str, partition: u32, dir: &Path) -> Result<()> {
        let mut files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("log"))
            .collect();
        files.sort();
        let mut part = PartitionLog::default();
        for path in files {
            let base = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let mut reader = BufReader::new(File::open(&path)?);
            let mut pos = 0u64;
            let mut line = String::new();
            loop {
                line.clear();
                let bytes = reader.read_line(&mut line)?;
                if bytes == 0 {
                    break;
                }
                let trimmed = line.trim_end();
                if !trimmed.is_empty() {
                    let stored: StoredRecord = serde_json::from_str(trimmed).map_err(|e| {
                        CoreError::Invalid(format!("corrupt segment {}: {e}", path.display()))
                    })?;
                    part.index.insert(
                        stored.offset,
                        OffsetPos {
                            segment: path.clone(),
                            pos,
                        },
                    );
                    part.next_offset = part.next_offset.max(stored.offset + 1);
                    part.current_base = base;
                }
                pos += bytes as u64;
            }
            part.current_size = fs::metadata(&path)?.len();
        }
        self.partitions.insert((topic.to_string(), partition), part);
        Ok(())
    }

    fn partition_dir(&self, topic: &str, partition: u32) -> PathBuf {
        self.root.join(topic).join(partition.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join("stream-core-tests")
            .join(format!("{name}-{n}"))
    }

    #[test]
    fn append_and_read() {
        let dir = test_dir("append");
        let mut log = CommitLog::open(&dir, 1024).unwrap();
        let written = log
            .append(
                "orders",
                0,
                vec![NewRecord {
                    key: Some("k".into()),
                    value: json!({"n":1}),
                }],
            )
            .unwrap();
        assert_eq!(written[0].offset, 0);
        let read = log.read_from("orders", 0, 0, 10).unwrap();
        assert_eq!(read, written);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn segment_rolls() {
        let dir = test_dir("roll");
        let mut log = CommitLog::open(&dir, 180).unwrap();
        for i in 0..10 {
            log.append(
                "t",
                0,
                vec![NewRecord {
                    key: None,
                    value: json!({"payload":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "i": i}),
                }],
            )
            .unwrap();
        }
        let seg_dir = dir.join("logs").join("t").join("0");
        let files = fs::read_dir(seg_dir).unwrap().count();
        assert!(files > 1, "expected multiple segments");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rebuilds_offsets() {
        let dir = test_dir("recovery");
        {
            let mut log = CommitLog::open(&dir, 256).unwrap();
            log.append(
                "events",
                1,
                vec![
                    NewRecord {
                        key: None,
                        value: json!("a"),
                    },
                    NewRecord {
                        key: None,
                        value: json!("b"),
                    },
                ],
            )
            .unwrap();
        }
        let mut recovered = CommitLog::open(&dir, 256).unwrap();
        assert_eq!(recovered.next_offset("events", 1), 2);
        let read = recovered.read_from("events", 1, 1, 1).unwrap();
        assert_eq!(read[0].value, json!("b"));
        let appended = recovered
            .append(
                "events",
                1,
                vec![NewRecord {
                    key: None,
                    value: json!("c"),
                }],
            )
            .unwrap();
        assert_eq!(appended[0].offset, 2);
        let _ = fs::remove_dir_all(dir);
    }
}
