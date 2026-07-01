use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub column: String,
    pub op: FilterOp,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregateOp {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSpec {
    pub op: AggregateOp,
    #[serde(default)]
    pub column: Option<String>,
    #[serde(default = "default_alias")]
    pub alias: String,
}

fn default_alias() -> String {
    "value".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Query {
    #[serde(default, rename = "where")]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub select: Option<Vec<String>>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub aggregate: Option<AggregateSpec>,
}

pub fn run_query(rows: &[Value], query: &Query) -> Result<Vec<Value>> {
    let filtered: Vec<&Value> = rows
        .iter()
        .filter(|row| matches_all(row, &query.filters))
        .collect();
    if let Some(group_col) = &query.group_by {
        let agg = query
            .aggregate
            .as_ref()
            .ok_or_else(|| CoreError::Invalid("group_by requires aggregate".into()))?;
        let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
        for row in filtered {
            groups
                .entry(group_key(row, group_col))
                .or_default()
                .push(row);
        }
        let mut out = Vec::new();
        for (key, group) in groups {
            let mut obj = Map::new();
            obj.insert(group_col.clone(), Value::String(key));
            obj.insert(agg.alias.clone(), aggregate(&group, agg)?);
            out.push(Value::Object(obj));
        }
        return Ok(out);
    }
    if let Some(agg) = &query.aggregate {
        let mut obj = Map::new();
        obj.insert(agg.alias.clone(), aggregate(&filtered, agg)?);
        return Ok(vec![Value::Object(obj)]);
    }
    Ok(filtered
        .into_iter()
        .map(|row| project(row, query.select.as_deref()))
        .collect())
}

fn matches_all(row: &Value, filters: &[Filter]) -> bool {
    filters.iter().all(|f| matches_filter(row, f))
}

fn matches_filter(row: &Value, filter: &Filter) -> bool {
    let Some(actual) = row.get(&filter.column) else {
        return false;
    };
    match filter.op {
        FilterOp::Eq => actual == &filter.value,
        FilterOp::Ne => actual != &filter.value,
        FilterOp::Gt => cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Greater),
        FilterOp::Lt => cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Less),
        FilterOp::Gte => cmp(actual, &filter.value)
            .is_some_and(|o| o == Ordering::Greater || o == Ordering::Equal),
        FilterOp::Lte => {
            cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Less || o == Ordering::Equal)
        }
        FilterOp::Contains => contains(actual, &filter.value),
    }
}

fn cmp(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn contains(actual: &Value, needle: &Value) -> bool {
    match (actual, needle) {
        (Value::String(h), Value::String(n)) => h.contains(n),
        (Value::Array(arr), v) => arr.iter().any(|x| x == v),
        _ => false,
    }
}

fn group_key(row: &Value, column: &str) -> String {
    match row.get(column) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "null".into(),
    }
}

fn number(v: f64) -> Value {
    Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn aggregate(rows: &[&Value], agg: &AggregateSpec) -> Result<Value> {
    match agg.op {
        AggregateOp::Count => Ok(Value::Number((rows.len() as u64).into())),
        AggregateOp::Sum | AggregateOp::Avg | AggregateOp::Min | AggregateOp::Max => {
            let col = agg
                .column
                .as_ref()
                .ok_or_else(|| CoreError::Invalid("numeric aggregate requires column".into()))?;
            let values: Vec<f64> = rows
                .iter()
                .filter_map(|r| r.get(col).and_then(Value::as_f64))
                .collect();
            if values.is_empty() {
                return Ok(Value::Null);
            }
            Ok(match agg.op {
                AggregateOp::Sum => number(values.iter().sum()),
                AggregateOp::Avg => number(values.iter().sum::<f64>() / values.len() as f64),
                AggregateOp::Min => number(values.into_iter().fold(f64::INFINITY, f64::min)),
                AggregateOp::Max => number(values.into_iter().fold(f64::NEG_INFINITY, f64::max)),
                AggregateOp::Count => unreachable!(),
            })
        }
    }
}

fn project(row: &Value, select: Option<&[String]>) -> Value {
    let Some(cols) = select else {
        return row.clone();
    };
    let mut obj = Map::new();
    for col in cols {
        if let Some(v) = row.get(col) {
            obj.insert(col.clone(), v.clone());
        }
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn group_by_sum_and_count() {
        let rows = vec![
            json!({"region":"eu","amount":10,"name":"alpha"}),
            json!({"region":"eu","amount":20,"name":"beta"}),
            json!({"region":"us","amount":7,"name":"gamma"}),
            json!({"region":"us","amount":3,"name":"alphabet"}),
        ];
        let q = Query {
            filters: vec![Filter {
                column: "name".into(),
                op: FilterOp::Contains,
                value: json!("a"),
            }],
            group_by: Some("region".into()),
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Sum,
                column: Some("amount".into()),
                alias: "total".into(),
            }),
            select: None,
        };
        let out = run_query(&rows, &q).unwrap();
        assert_eq!(
            out,
            vec![
                json!({"region":"eu","total":30.0}),
                json!({"region":"us","total":10.0})
            ]
        );
    }

    #[test]
    fn filters_and_avg() {
        let rows = vec![
            json!({"kind":"a","v":1}),
            json!({"kind":"a","v":3}),
            json!({"kind":"b","v":99}),
        ];
        let q = Query {
            filters: vec![Filter {
                column: "kind".into(),
                op: FilterOp::Eq,
                value: json!("a"),
            }],
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Avg,
                column: Some("v".into()),
                alias: "avg_v".into(),
            }),
            ..Default::default()
        };
        assert_eq!(run_query(&rows, &q).unwrap(), vec![json!({"avg_v":2.0})]);
    }
}
