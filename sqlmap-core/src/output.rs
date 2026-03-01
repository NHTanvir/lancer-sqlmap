//! Pluggable output writers. Mirrors upstream `--dump-format` plus the
//! Lancer-wide JSON / SARIF / Markdown emitters used by the GUI export menu.

use crate::enumerator::DumpedTable;
use crate::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Text,
    Csv,
    Html,
    Json,
    Sqlite,
    Markdown,
    Sarif,
}

pub struct OutputWriter;

impl OutputWriter {
    pub fn render_table(table: &DumpedTable, fmt: OutputFormat) -> Result<String> {
        Ok(match fmt {
            OutputFormat::Text | OutputFormat::Markdown => render_md(table),
            OutputFormat::Csv => render_csv(table, ','),
            OutputFormat::Html => render_html(table),
            OutputFormat::Json => serde_json::to_string_pretty(table)?,
            OutputFormat::Sqlite => format!("-- target: sqlite emitter goes to file, not string\n{}", render_md(table)),
            OutputFormat::Sarif => render_sarif(table),
        })
    }
}

fn render_md(t: &DumpedTable) -> String {
    let mut s = String::new();
    s.push_str(&format!("### `{}` . `{}`\n\n", t.db, t.table));
    if !t.columns.is_empty() {
        s.push_str("| ");
        s.push_str(&t.columns.join(" | "));
        s.push_str(" |\n| ");
        s.push_str(&t.columns.iter().map(|_| "---").collect::<Vec<_>>().join(" | "));
        s.push_str(" |\n");
    }
    for r in &t.rows {
        s.push_str("| ");
        s.push_str(&r.values.iter().map(|v| v.replace('|', "\\|")).collect::<Vec<_>>().join(" | "));
        s.push_str(" |\n");
    }
    s
}

fn render_csv(t: &DumpedTable, sep: char) -> String {
    let mut s = String::new();
    s.push_str(&t.columns.join(&sep.to_string()));
    s.push('\n');
    for r in &t.rows {
        s.push_str(&r.values.iter().map(|v| csv_escape(v, sep)).collect::<Vec<_>>().join(&sep.to_string()));
        s.push('\n');
    }
    s
}

fn csv_escape(v: &str, sep: char) -> String {
    if v.contains(sep) || v.contains('"') || v.contains('\n') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

fn render_html(t: &DumpedTable) -> String {
    let mut s = String::new();
    s.push_str(&format!("<h3>{}.{}</h3>\n<table border=\"1\"><tr>", html_esc(&t.db), html_esc(&t.table)));
    for c in &t.columns {
        s.push_str(&format!("<th>{}</th>", html_esc(c)));
    }
    s.push_str("</tr>\n");
    for r in &t.rows {
        s.push_str("<tr>");
        for v in &r.values {
            s.push_str(&format!("<td>{}</td>", html_esc(v)));
        }
        s.push_str("</tr>\n");
    }
    s.push_str("</table>");
    s
}

fn html_esc(v: &str) -> String {
    v.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn render_sarif(t: &DumpedTable) -> String {
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "lancer-sqlmap", "version": "0.1" } },
            "results": [{
                "ruleId": "sqli-dump",
                "level": "warning",
                "message": { "text": format!("Dumped {}.{} ({} rows)", t.db, t.table, t.rows.len()) },
            }]
        }]
    });
    sarif.to_string()
}
