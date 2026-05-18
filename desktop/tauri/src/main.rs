#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

type BackendChild = Arc<Mutex<Option<Child>>>;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(r"..\..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r"..\.."))
}

fn backend_running() -> bool {
    TcpStream::connect("127.0.0.1:8000").is_ok()
}

fn spawn_backend() -> std::io::Result<Child> {
    let root = workspace_root();
    let python = root.join(".venv").join("Scripts").join("python.exe");
    let backend_dir = root.join("backend");

    Command::new(python)
        .current_dir(backend_dir)
        .args(["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

#[tauri::command]
fn start_backend(state: tauri::State<BackendChild>) -> bool {
    if backend_running() {
        return true;
    }
    match spawn_backend() {
        Ok(child) => {
            if let Ok(mut slot) = state.lock() {
                *slot = Some(child);
            }
            true
        }
        Err(err) => {
            eprintln!("failed to start backend on demand: {err}");
            false
        }
    }
}

#[tauri::command]
fn restart_backend(state: tauri::State<BackendChild>) -> bool {
    // Kill existing process if we have one
    if let Ok(mut slot) = state.lock() {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    // Small sleep to let the port free up
    std::thread::sleep(std::time::Duration::from_millis(800));
    match spawn_backend() {
        Ok(child) => {
            if let Ok(mut slot) = state.lock() {
                *slot = Some(child);
            }
            true
        }
        Err(err) => {
            eprintln!("failed to restart backend: {err}");
            false
        }
    }
}

fn main() {
    let backend_child: BackendChild = Arc::new(Mutex::new(None));
    let backend_on_setup = Arc::clone(&backend_child);
    let backend_on_exit = Arc::clone(&backend_child);

    let app = tauri::Builder::default()
        .manage(Arc::clone(&backend_child))
        .invoke_handler(tauri::generate_handler![start_backend, restart_backend])
        .setup(move |_app| {
            if !backend_running() {
                match spawn_backend() {
                    Ok(child) => {
                        if let Ok(mut slot) = backend_on_setup.lock() {
                            *slot = Some(child);
                        }
                    }
                    Err(err) => {
                        eprintln!("failed to start backend: {err}");
                    }
                }
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(move |_app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit) {
            if let Ok(mut slot) = backend_on_exit.lock() {
                if let Some(mut child) = slot.take() {
                    let _ = child.kill();
                }
            }
        }
    });
}
