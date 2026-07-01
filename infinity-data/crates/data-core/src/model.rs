use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    Cosine,
    L2,
    Dot,
}

impl Metric {
    pub fn distance(self, a: &[f32], b: &[f32]) -> f32 {
        match self {
            Metric::Cosine => {
                let mut dot = 0.0;
                let mut na = 0.0;
                let mut nb = 0.0;
                for (x, y) in a.iter().zip(b) {
                    dot += x * y;
                    na += x * x;
                    nb += y * y;
                }
                if na <= f32::EPSILON || nb <= f32::EPSILON {
                    1.0
                } else {
                    1.0 - dot / (na.sqrt() * nb.sqrt())
                }
            }
            Metric::L2 => a
                .iter()
                .zip(b)
                .map(|(x, y)| (x - y) * (x - y))
                .sum::<f32>()
                .sqrt(),
            Metric::Dot => -a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>(),
        }
    }

    pub fn score(self, a: &[f32], b: &[f32]) -> f32 {
        match self {
            Metric::Cosine => 1.0 - self.distance(a, b),
            Metric::L2 => -self.distance(a, b),
            Metric::Dot => -self.distance(a, b),
        }
    }
}

impl FromStr for Metric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "cosine" => Ok(Metric::Cosine),
            "l2" | "euclidean" => Ok(Metric::L2),
            "dot" | "inner" => Ok(Metric::Dot),
            _ => Err(format!("unsupported metric: {s}")),
        }
    }
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Metric::Cosine => "cosine",
            Metric::L2 => "l2",
            Metric::Dot => "dot",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionInfo {
    pub name: String,
    pub dim: usize,
    pub metric: Metric,
    pub count: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<TableColumn>,
    pub row_count: usize,
    pub created_at: String,
}
