use chrono::Local;
use colored::*;
use std::fs::{OpenOptions, File};
use std::io::Write;
use std::sync::Mutex;
use once_cell::sync::Lazy;

static LOG_FILE: Lazy<Mutex<Option<File>>> = Lazy::new(|| {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("sx_panel.log")
        .ok();
    Mutex::new(file)
});

pub fn timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn log_info(msg: &str) {
    let line = format!("[{}] [INFO]  {}", timestamp(), msg);
    println!("{}", line.cyan());
    write_log(&line);
}

pub fn log_success(msg: &str) {
    let line = format!("[{}] [OK]    {}", timestamp(), msg);
    println!("{}", line.green().bold());
    write_log(&line);
}

pub fn log_warn(msg: &str) {
    let line = format!("[{}] [WARN]  {}", timestamp(), msg);
    println!("{}", line.yellow());
    write_log(&line);
}

pub fn log_error(msg: &str) {
    let line = format!("[{}] [ERROR] {}", timestamp(), msg);
    println!("{}", line.red());
    write_log(&line);
}

pub fn log_attack(msg: &str) {
    let line = format!("[{}] [ATCK]  {}", timestamp(), msg);
    println!("{}", line.magenta().bold());
    write_log(&line);
}

pub fn log_stat(msg: &str) {
    let line = format!("[{}] [STAT]  {}", timestamp(), msg);
    println!("{}", line.bright_blue());
    write_log(&line);
}

fn write_log(line: &str) {
    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut file) = *guard {
            let _ = writeln!(file, "{}", line);
        }
    }
}
