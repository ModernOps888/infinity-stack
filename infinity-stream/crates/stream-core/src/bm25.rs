use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct Bm25Index {
    docs: HashMap<String, HashMap<String, Value>>,
    postings: HashMap<String, HashMap<String, u32>>,
    doc_lengths: HashMap<String, usize>,
    total_doc_len: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoredDoc {
    pub doc_id: String,
    pub score: f64,
}

impl Bm25Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn index(&mut self, doc_id: impl Into<String>, fields: HashMap<String, Value>) {
        let doc_id = doc_id.into();
        if self.docs.contains_key(&doc_id) {
            self.remove(&doc_id);
        }
        let tokens = tokenize(&fields_to_text(&fields));
        let len = tokens.len().max(1);
        let mut tf: HashMap<String, u32> = HashMap::new();
        for t in tokens {
            *tf.entry(t).or_insert(0) += 1;
        }
        for (term, count) in tf {
            self.postings
                .entry(term)
                .or_default()
                .insert(doc_id.clone(), count);
        }
        self.doc_lengths.insert(doc_id.clone(), len);
        self.total_doc_len += len;
        self.docs.insert(doc_id, fields);
    }

    pub fn remove(&mut self, doc_id: &str) {
        if self.docs.remove(doc_id).is_some() {
            if let Some(len) = self.doc_lengths.remove(doc_id) {
                self.total_doc_len = self.total_doc_len.saturating_sub(len);
            }
            let terms: Vec<String> = self.postings.keys().cloned().collect();
            for term in terms {
                if let Some(p) = self.postings.get_mut(&term) {
                    p.remove(doc_id);
                    if p.is_empty() {
                        self.postings.remove(&term);
                    }
                }
            }
        }
    }

    pub fn search(&self, query: &str, k: usize) -> Vec<ScoredDoc> {
        let q_terms = tokenize(query);
        if q_terms.is_empty() || self.docs.is_empty() || k == 0 {
            return vec![];
        }
        let n = self.docs.len() as f64;
        let avgdl = (self.total_doc_len as f64 / n).max(1.0);
        let k1 = 1.2;
        let b = 0.75;
        let mut scores: HashMap<String, f64> = HashMap::new();
        let unique: HashSet<String> = q_terms.into_iter().collect();
        for term in unique {
            let Some(posting) = self.postings.get(&term) else {
                continue;
            };
            let df = posting.len() as f64;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            for (doc, tf) in posting {
                let freq = *tf as f64;
                let dl = *self.doc_lengths.get(doc).unwrap_or(&1) as f64;
                let denom = freq + k1 * (1.0 - b + b * dl / avgdl);
                *scores.entry(doc.clone()).or_insert(0.0) += idf * (freq * (k1 + 1.0)) / denom;
            }
        }
        let mut ranked: Vec<ScoredDoc> = scores
            .into_iter()
            .map(|(doc_id, score)| ScoredDoc { doc_id, score })
            .collect();
        ranked.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.doc_id.cmp(&b.doc_id))
        });
        ranked.truncate(k);
        ranked
    }
}

pub fn tokenize(input: &str) -> Vec<String> {
    input
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty() && !STOPWORDS.contains(s))
        .map(ToOwned::to_owned)
        .collect()
}

fn fields_to_text(fields: &HashMap<String, Value>) -> String {
    fn push_value(out: &mut String, v: &Value) {
        match v {
            Value::String(s) => {
                out.push(' ');
                out.push_str(s);
            }
            Value::Number(n) => {
                out.push(' ');
                out.push_str(&n.to_string());
            }
            Value::Bool(b) => {
                out.push(' ');
                out.push_str(if *b { "true" } else { "false" });
            }
            Value::Array(a) => {
                for v in a {
                    push_value(out, v);
                }
            }
            Value::Object(o) => {
                for v in o.values() {
                    push_value(out, v);
                }
            }
            Value::Null => {}
        }
    }
    let mut out = String::new();
    for (k, v) in fields {
        out.push(' ');
        out.push_str(k);
        push_value(&mut out, v);
    }
    out
}

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he", "in", "is", "it",
    "its", "of", "on", "that", "the", "to", "was", "were", "will", "with", "or", "this", "these",
    "those",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(title: &str, body: &str) -> HashMap<String, Value> {
        HashMap::from([("title".into(), json!(title)), ("body".into(), json!(body))])
    }

    #[test]
    fn tokenizes_and_removes_stopwords() {
        assert_eq!(
            tokenize("The Quick, brown fox!"),
            vec!["quick", "brown", "fox"]
        );
    }

    #[test]
    fn relevant_docs_rank_above_irrelevant() {
        let mut idx = Bm25Index::new();
        idx.index(
            "rust",
            doc("Rust streaming", "append only logs and fast search"),
        );
        idx.index("cake", doc("Cake recipe", "flour sugar butter"));
        idx.index(
            "logs",
            doc("Streaming logs", "durable commit logs search search"),
        );
        let hits = idx.search("streaming commit logs", 3);
        assert_eq!(hits[0].doc_id, "logs");
        assert!(
            hits.iter().position(|h| h.doc_id == "logs").unwrap()
                < hits
                    .iter()
                    .position(|h| h.doc_id == "cake")
                    .unwrap_or(usize::MAX)
        );
    }
}
