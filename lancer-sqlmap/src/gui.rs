//! eframe / egui GUI — the default UI when the binary is launched with no
//! `--cli` flag.
//!
//! Layout (matches `## GUI (Lancer-standard pattern)` in the plan):
//!
//! ```text
//!  File  Tools  Settings  Help                                              [≡]
//! ┌──────────┬─────────────────────────────────────┬───────────────────────┐
//! │  Inputs  │            Main view                │      Detail pane      │
//! │  Jobs    │         (findings table)            │ (working payload,     │
//! │  Scope   │                                     │  evidence, remed.)    │
//! └──────────┴─────────────────────────────────────┴───────────────────────┘
//!  Status: idle    Items: 0                     [Open] [Run] [Export]
//! ```

#![cfg(feature = "gui")]

use eframe::egui;
use eframe::App;
use parking_lot::Mutex;
use sqlmap_core::reports::{Finding, FindingSeverity, ReportBundle};
use std::sync::Arc;

pub fn launch() -> eframe::Result<()> {
    let native_opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("lancer-sqlmap")
            .with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-sqlmap",
        native_opts,
        Box::new(|_cc| Ok(Box::new(GuiApp::default()))),
    )
}

pub struct GuiApp {
    // Inputs / left panel state
    url_input: String,
    request_file_input: String,
    technique_input: String,
    level_input: u8,
    risk_input: u8,
    dbms_input: String,
    tamper_input: String,

    // Center: findings list
    findings: Arc<Mutex<Vec<Finding>>>,
    selected: Option<usize>,
    status_line: Arc<Mutex<String>>,
    running: Arc<Mutex<bool>>,

    // Settings
    dark_mode: bool,
}

impl Default for GuiApp {
    fn default() -> Self {
        Self {
            url_input: String::new(),
            request_file_input: String::new(),
            technique_input: "BEUSTQ".into(),
            level_input: 1,
            risk_input: 1,
            dbms_input: String::new(),
            tamper_input: String::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            selected: None,
            status_line: Arc::new(Mutex::new("idle".into())),
            running: Arc::new(Mutex::new(false)),
            dark_mode: true,
        }
    }
}

impl App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.dark_mode { ctx.set_visuals(egui::Visuals::dark()); } else { ctx.set_visuals(egui::Visuals::light()); }

        // ── Menu ──
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open request.txt…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.request_file_input = path.display().to_string();
                        }
                    }
                    if ui.button("Save findings (JSON)…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().save_file() {
                            let v = self.findings.lock().clone();
                            let _ = std::fs::write(path, serde_json::to_string_pretty(&v).unwrap_or_default());
                        }
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("SQL Shell").clicked() {
                        *self.status_line.lock() = "SQL shell: requires confirmed injection".into();
                    }
                    if ui.button("OS Shell").clicked() {
                        *self.status_line.lock() = "OS shell: requires confirmed injection + privileges".into();
                    }
                    if ui.button("List tampers").clicked() {
                        let n = sqlmap_tamper::scripts::catalog().len();
                        *self.status_line.lock() = format!("{n} built-in tampers");
                    }
                });
                ui.menu_button("Settings", |ui| {
                    ui.checkbox(&mut self.dark_mode, "Dark mode");
                });
                ui.menu_button("Help", |ui| {
                    ui.label("lancer-sqlmap v0.1");
                    ui.label("Part of the Lancer bug bounty toolkit.");
                    ui.label("Plan: workspace plan.md (local).");
                });
            });
        });

        // ── Status bar ──
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let s = self.status_line.lock().clone();
                ui.label(format!("Status: {s}"));
                let n = self.findings.lock().len();
                ui.label(format!("Items: {n}"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() { self.export(); }
                    if ui.button("Run").clicked() { self.start_run(ctx.clone()); }
                    if ui.button("Open").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.request_file_input = path.display().to_string();
                        }
                    }
                });
            });
        });

        // ── Left: inputs ──
        egui::SidePanel::left("inputs").default_width(280.0).show(ctx, |ui| {
            ui.heading("Target");
            ui.label("URL");
            ui.text_edit_singleline(&mut self.url_input);
            ui.label("Request file");
            ui.text_edit_singleline(&mut self.request_file_input);
            ui.separator();
            ui.heading("Detection");
            ui.horizontal(|ui| {
                ui.label("Level");
                ui.add(egui::Slider::new(&mut self.level_input, 1..=5));
            });
            ui.horizontal(|ui| {
                ui.label("Risk");
                ui.add(egui::Slider::new(&mut self.risk_input, 1..=3));
            });
            ui.label("Techniques");
            ui.text_edit_singleline(&mut self.technique_input);
            ui.separator();
            ui.heading("DBMS");
            ui.text_edit_singleline(&mut self.dbms_input);
            ui.separator();
            ui.heading("Tampers (comma)");
            ui.text_edit_singleline(&mut self.tamper_input);
            if ui.button("Validate tamper chain").clicked() {
                let names: Vec<&str> = self.tamper_input.split(',').map(|s| s.trim()).collect();
                let res = sqlmap_tamper::TamperChain::from_names(&names);
                *self.status_line.lock() = match res {
                    Ok(c) => format!("chain ok ({} entries)", c.len()),
                    Err(e) => format!("chain invalid: {e}"),
                };
            }
        });

        // ── Right: detail ──
        egui::SidePanel::right("detail").default_width(360.0).show(ctx, |ui| {
            ui.heading("Finding detail");
            let v = self.findings.lock();
            if let Some(i) = self.selected.and_then(|i| if i < v.len() { Some(i) } else { None }) {
                let f = &v[i];
                ui.label(format!("Title: {}", f.title));
                ui.label(format!("Severity: {:?}", f.severity));
                ui.label(format!("Param: {}", f.param));
                ui.label(format!("Technique: {}", f.technique));
                if let Some(d) = f.dbms {
                    ui.label(format!("DBMS: {}", d));
                }
                ui.label("Working payload:");
                ui.add(egui::TextEdit::multiline(&mut f.working_payload.clone()).desired_rows(3));
                ui.label("Evidence:");
                ui.label(&f.evidence);
                ui.separator();
                ui.label("Remediation");
                ui.label(&f.remediation);
                if ui.button("Copy payload").clicked() {
                    if let Ok(mut clip) = arboard::Clipboard::new() {
                        let _ = clip.set_text(f.working_payload.clone());
                        *self.status_line.lock() = "payload copied".into();
                    }
                }
            } else {
                ui.label("No finding selected.");
            }
        });

        // ── Center: findings list ──
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Findings");
            let v = self.findings.lock();
            egui::Grid::new("findings_grid").striped(true).show(ui, |ui| {
                ui.label("#");
                ui.label("Title");
                ui.label("Param");
                ui.label("Technique");
                ui.label("DBMS");
                ui.label("Severity");
                ui.end_row();
                for (i, f) in v.iter().enumerate() {
                    let row = ui.selectable_label(self.selected == Some(i), format!("{}", i + 1));
                    if row.clicked() {
                        self.selected = Some(i);
                    }
                    ui.label(&f.title);
                    ui.label(&f.param);
                    ui.label(format!("{}", f.technique));
                    ui.label(f.dbms.map(|d| d.short().to_string()).unwrap_or_default());
                    ui.label(format!("{:?}", f.severity));
                    ui.end_row();
                }
            });
        });
    }
}

impl GuiApp {
    fn start_run(&mut self, _ctx: egui::Context) {
        if *self.running.lock() {
            return;
        }
        *self.status_line.lock() = "running…".into();
        *self.running.lock() = true;
        // For an in-process demo run we just produce a synthetic finding —
        // a full async detection requires shipping the CLI args struct over;
        // the GUI exposes the same surface, but the actual run is launched
        // by the main entry point when the user double-clicks the binary.
        let findings = self.findings.clone();
        let status = self.status_line.lock().clone();
        let running = self.running.clone();
        std::thread::spawn(move || {
            let _ = status;
            // Placeholder: emit a "scaffold" finding so the table renders.
            findings.lock().push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                title: "GUI demo — replace with actual run".into(),
                severity: FindingSeverity::Info,
                target_url: "(none)".into(),
                param: "(none)".into(),
                technique: 'B',
                dbms: None,
                working_payload: String::new(),
                evidence: "GUI dry run".into(),
                remediation: "Provide --url or --request to launch a real run.".into(),
                created_at: chrono::Utc::now().timestamp(),
            });
            *running.lock() = false;
        });
    }

    fn export(&self) {
        let Some(path) = rfd::FileDialog::new().save_file() else { return };
        let v = self.findings.lock().clone();
        let bundle = ReportBundle {
            findings: v,
            session_path: None,
            har_path: None,
            started_at: 0,
            finished_at: chrono::Utc::now().timestamp(),
        };
        let _ = std::fs::write(path, serde_json::to_string_pretty(&bundle).unwrap_or_default());
        *self.status_line.lock() = "exported".into();
    }
}
