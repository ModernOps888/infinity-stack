use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::{CoreError, Result};
use crate::model::Metric;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub id: String,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub distance: f32,
    pub score: f32,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Node {
    id: String,
    vector: Vec<f32>,
    metadata: Option<Value>,
    level: usize,
    neighbors: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HnswIndex {
    dim: usize,
    metric: Metric,
    m: usize,
    ef_construction: usize,
    max_level: usize,
    entry_point: Option<String>,
    nodes: HashMap<String, Node>,
}

impl HnswIndex {
    pub fn new(dim: usize, metric: Metric, m: usize, ef_construction: usize) -> Result<Self> {
        if dim == 0 { return Err(CoreError::Invalid("dimension must be > 0".into())); }
        Ok(Self {
            dim,
            metric,
            m: m.max(2),
            ef_construction: ef_construction.max(m.max(2)),
            max_level: 0,
            entry_point: None,
            nodes: HashMap::new(),
        })
    }

    pub fn dim(&self) -> usize { self.dim }
    pub fn metric(&self) -> Metric { self.metric }
    pub fn len(&self) -> usize { self.nodes.len() }
    pub fn is_empty(&self) -> bool { self.nodes.is_empty() }
    pub fn point(&self, id: &str) -> Option<Point> {
        self.nodes.get(id).map(|n| Point { id: n.id.clone(), vector: n.vector.clone(), metadata: n.metadata.clone() })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() { std::fs::create_dir_all(parent)?; }
        let data = serde_json::to_vec(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn insert(&mut self, point: Point) -> Result<()> {
        if point.vector.len() != self.dim {
            return Err(CoreError::Invalid(format!("vector dimension {} does not match collection dimension {}", point.vector.len(), self.dim)));
        }
        if self.nodes.contains_key(&point.id) {
            self.delete(&point.id);
        }

        let level = self.random_level();
        let id = point.id.clone();
        let node = Node {
            id: id.clone(),
            vector: point.vector.clone(),
            metadata: point.metadata.clone(),
            level,
            neighbors: vec![Vec::new(); level + 1],
        };

        if self.entry_point.is_none() {
            self.max_level = level;
            self.entry_point = Some(id.clone());
            self.nodes.insert(id, node);
            return Ok(());
        }

        let mut entry = self.entry_point.clone().unwrap();
        for layer in ((level + 1)..=self.max_level).rev() {
            entry = self.greedy_closest(&point.vector, &entry, layer);
        }

        self.nodes.insert(id.clone(), node);
        let upto = level.min(self.max_level);
        for layer in (0..=upto).rev() {
            let found = self.search_layer(&point.vector, &entry, self.ef_construction, layer);
            let selected = self.select_neighbors(found, self.m);
            for neighbor in selected {
                self.link(&id, &neighbor, layer);
            }
            if let Some(best) = self.nodes.get(&id).and_then(|n| n.neighbors.get(layer)).and_then(|v| v.first()).cloned() {
                entry = best;
            }
        }

        if level > self.max_level {
            self.max_level = level;
            self.entry_point = Some(id);
        }
        Ok(())
    }

    pub fn upsert_many(&mut self, points: Vec<Point>) -> Result<()> {
        for p in points { self.insert(p)?; }
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let existed = self.nodes.remove(id).is_some();
        if !existed { return false; }
        for node in self.nodes.values_mut() {
            for layer in &mut node.neighbors { layer.retain(|n| n != id); }
        }
        if self.entry_point.as_deref() == Some(id) {
            self.entry_point = self.nodes.keys().next().cloned();
            self.max_level = self.nodes.values().map(|n| n.level).max().unwrap_or(0);
        }
        existed
    }

    pub fn search(&self, query: &[f32], k: usize, ef: usize) -> Result<Vec<SearchHit>> {
        if query.len() != self.dim {
            return Err(CoreError::Invalid(format!("query dimension {} does not match collection dimension {}", query.len(), self.dim)));
        }
        if k == 0 || self.nodes.is_empty() { return Ok(Vec::new()); }
        let mut entry = self.entry_point.clone().unwrap();
        for layer in (1..=self.max_level).rev() {
            entry = self.greedy_closest(query, &entry, layer);
        }
        let ef = ef.max(k).min(self.nodes.len().max(k));
        let candidates = self.search_layer(query, &entry, ef, 0);
        let mut hits: Vec<_> = candidates.into_iter().take(k).filter_map(|(distance, id)| {
            self.nodes.get(&id).map(|n| SearchHit {
                id: id.clone(),
                distance,
                score: self.metric.score(query, &n.vector),
                metadata: n.metadata.clone(),
            })
        }).collect();
        hits.sort_by(|a, b| a.distance.partial_cmp(&b.distance).unwrap_or(Ordering::Equal));
        Ok(hits)
    }

    pub fn brute_force_search(&self, query: &[f32], k: usize) -> Result<Vec<SearchHit>> {
        if query.len() != self.dim {
            return Err(CoreError::Invalid(format!("query dimension {} does not match collection dimension {}", query.len(), self.dim)));
        }
        let mut hits: Vec<_> = self.nodes.values().map(|n| {
            let distance = self.metric.distance(query, &n.vector);
            SearchHit { id: n.id.clone(), distance, score: self.metric.score(query, &n.vector), metadata: n.metadata.clone() }
        }).collect();
        hits.sort_by(|a, b| a.distance.partial_cmp(&b.distance).unwrap_or(Ordering::Equal));
        hits.truncate(k);
        Ok(hits)
    }

    fn random_level(&self) -> usize {
        let mut rng = rand::thread_rng();
        let p = 1.0 / (self.m as f64).ln().max(1.0);
        let mut level = 0;
        while rng.gen::<f64>() < p && level < 32 { level += 1; }
        level
    }

    fn dist(&self, query: &[f32], id: &str) -> f32 {
        self.nodes.get(id).map(|n| self.metric.distance(query, &n.vector)).unwrap_or(f32::INFINITY)
    }

    fn greedy_closest(&self, query: &[f32], entry: &str, layer: usize) -> String {
        let mut current = entry.to_string();
        let mut current_dist = self.dist(query, &current);
        loop {
            let mut changed = false;
            if let Some(node) = self.nodes.get(&current) {
                if let Some(neighbors) = node.neighbors.get(layer) {
                    for nb in neighbors {
                        let d = self.dist(query, nb);
                        if d < current_dist {
                            current_dist = d;
                            current = nb.clone();
                            changed = true;
                        }
                    }
                }
            }
            if !changed { break; }
        }
        current
    }

    fn search_layer(&self, query: &[f32], entry: &str, ef: usize, layer: usize) -> Vec<(f32, String)> {
        let mut visited = HashSet::new();
        let mut candidates = vec![(self.dist(query, entry), entry.to_string())];
        let mut results = candidates.clone();
        visited.insert(entry.to_string());

        while !candidates.is_empty() {
            candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
            let (cand_dist, cand_id) = candidates.remove(0);
            results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
            let worst = results.last().map(|x| x.0).unwrap_or(f32::INFINITY);
            if results.len() >= ef && cand_dist > worst { break; }
            let neighbors = self.nodes.get(&cand_id)
                .and_then(|n| n.neighbors.get(layer))
                .cloned()
                .unwrap_or_default();
            for nb in neighbors {
                if !visited.insert(nb.clone()) { continue; }
                let d = self.dist(query, &nb);
                let worst = results.last().map(|x| x.0).unwrap_or(f32::INFINITY);
                if results.len() < ef || d < worst {
                    candidates.push((d, nb.clone()));
                    results.push((d, nb));
                    results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
                    if results.len() > ef { results.pop(); }
                }
            }
        }
        results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
        results
    }

    fn select_neighbors(&self, mut candidates: Vec<(f32, String)>, m: usize) -> Vec<String> {
        candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
        candidates.into_iter().take(m).map(|(_, id)| id).collect()
    }

    fn link(&mut self, a: &str, b: &str, layer: usize) {
        if a == b { return; }
        if let Some(an) = self.nodes.get_mut(a) {
            if layer < an.neighbors.len() && !an.neighbors[layer].iter().any(|x| x == b) {
                an.neighbors[layer].push(b.to_string());
            }
        }
        if let Some(bn) = self.nodes.get_mut(b) {
            if layer < bn.neighbors.len() && !bn.neighbors[layer].iter().any(|x| x == a) {
                bn.neighbors[layer].push(a.to_string());
            }
        }
        self.prune_neighbors(a, layer);
        self.prune_neighbors(b, layer);
    }

    fn prune_neighbors(&mut self, id: &str, layer: usize) {
        let Some(center) = self.nodes.get(id).map(|n| n.vector.clone()) else { return; };
        let Some(mut neighbors) = self.nodes.get(id).and_then(|n| n.neighbors.get(layer)).cloned() else { return; };
        let metric = self.metric;
        neighbors.sort_by(|x, y| {
            let dx = self.nodes.get(x).map(|n| metric.distance(&center, &n.vector)).unwrap_or(f32::INFINITY);
            let dy = self.nodes.get(y).map(|n| metric.distance(&center, &n.vector)).unwrap_or(f32::INFINITY);
            dx.partial_cmp(&dy).unwrap_or(Ordering::Equal)
        });
        if neighbors.len() > self.m { neighbors.truncate(self.m); }
        if let Some(node) = self.nodes.get_mut(id) {
            if layer < node.neighbors.len() {
                node.neighbors[layer] = neighbors;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;

    fn rand_vec(rng: &mut StdRng, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| rng.gen_range(-1.0..1.0)).collect()
    }

    #[test]
    fn hnsw_recall_vs_bruteforce_is_high() {
        let mut rng = StdRng::seed_from_u64(42);
        let dim = 32;
        let mut index = HnswIndex::new(dim, Metric::Cosine, 16, 128).unwrap();
        for i in 0..2500 {
            index.insert(Point { id: format!("p{i}"), vector: rand_vec(&mut rng, dim), metadata: None }).unwrap();
        }
        let mut recall_sum = 0.0;
        let queries = 20;
        for _ in 0..queries {
            let q = rand_vec(&mut rng, dim);
            let exact: HashSet<_> = index.brute_force_search(&q, 10).unwrap().into_iter().map(|h| h.id).collect();
            let approx: HashSet<_> = index.search(&q, 10, 512).unwrap().into_iter().map(|h| h.id).collect();
            let overlap = exact.intersection(&approx).count();
            recall_sum += overlap as f32 / 10.0;
        }
        let recall = recall_sum / queries as f32;
        eprintln!("HNSW recall@10={recall:.3}");
        assert!(recall > 0.90, "recall@10 too low: {recall}");
    }

    #[test]
    fn persists_roundtrip() {
        let mut index = HnswIndex::new(3, Metric::L2, 8, 32).unwrap();
        index.insert(Point { id: "a".into(), vector: vec![0.0, 1.0, 2.0], metadata: Some(serde_json::json!({"kind":"x"})) }).unwrap();
        let path = std::env::current_dir().unwrap().join("target").join("hnsw_test.idx");
        index.save(&path).unwrap();
        let loaded = HnswIndex::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.search(&[0.0, 1.0, 2.0], 1, 10).unwrap()[0].id, "a");
        let _ = std::fs::remove_file(path);
    }
}
