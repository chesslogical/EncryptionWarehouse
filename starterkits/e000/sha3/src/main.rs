// src/main.rs
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use sha3::{Digest, Sha3_512};

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "SHA3-512 Hasher",
        native_options,
        Box::new(|_cc| Ok(Box::new(HasherApp::default()))),
    )
}

#[derive(Default)]
struct HasherApp {
    input: String,
    output: String,
    uppercase: bool,
    live: bool,
}

impl HasherApp {
    fn recompute(&mut self) {
        let mut hasher = Sha3_512::new();
        hasher.update(self.input.as_bytes());
        let digest = hasher.finalize();
        self.output = if self.uppercase {
            hex::encode_upper(digest)
        } else {
            hex::encode(digest)
        };
    }
}

impl eframe::App for HasherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SHA3-512 Hasher");
            ui.separator();

            ui.label("Input text (hashed as UTF-8 bytes):");
            let response = ui.add(
                egui::TextEdit::multiline(&mut self.input)
                    .desired_rows(6)
                    .desired_width(f32::INFINITY),
            );

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.live, "Hash as you type");
                let upper_changed = ui.checkbox(&mut self.uppercase, "Uppercase hex").changed();

                if ui.button("Compute").clicked() {
                    self.recompute();
                }
                if ui.button("Clear").clicked() {
                    self.input.clear();
                    self.output.clear();
                }
                if upper_changed && !self.output.is_empty() {
                    self.recompute();
                }
            });

            if self.live && response.changed() {
                self.recompute();
            }

            ui.add_space(8.0);
            ui.label(format!("Input length: {} bytes", self.input.as_bytes().len()));
            ui.separator();

            ui.label("SHA3-512 (hex):");
            ui.add_enabled(
                false,
                egui::TextEdit::multiline(&mut self.output)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );

            ui.horizontal(|ui| {
                if ui.button("Copy result").clicked() && !self.output.is_empty() {
                    // Fixed: avoid deprecated PlatformOutput::copied_text
                    ui.ctx().copy_text(self.output.clone());
                }
                if ui.button("Test with \"abc\"").clicked() {
                    self.input = "abc".to_owned();
                    self.recompute();
                }
            });
        });
    }
}
