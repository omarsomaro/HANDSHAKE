use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use tauri::{Manager, State};
use tauri_plugin_shell::{process::{CommandChild, CommandEvent}, ShellExt};

#[derive(Default)]
struct DaemonState(Mutex<DaemonHandle>);

#[derive(Default)]
struct DaemonHandle {
  child: Option<CommandChild>,
  pid: Option<u32>,
  token_file: Option<PathBuf>,
  last_error: Option<String>,
  last_exit_code: Option<i32>,
  log_tail: VecDeque<String>,
}

#[derive(serde::Serialize)]
struct StartResult {
  pid: u32,
  api_url: String,
  token_file_path: String,
  token_required: bool,
}

#[derive(serde::Serialize)]
struct StatusResult {
  running: bool,
  pid: Option<u32>,
  last_error: Option<String>,
  last_exit_code: Option<i32>,
}

#[tauri::command]
async fn start_daemon(
  app: tauri::AppHandle,
  api_bind: String,
  unsafe_expose_api: bool,
  pluggable_transport: Option<String>,
  realtls_domain: Option<String>,
  stealth_mode: Option<String>,
  assist_relays: Option<String>,
  tor_socks_addr: Option<String>,
  tor_onion_addr: Option<String>,
  state: State<'_, DaemonState>,
) -> Result<StartResult, String> {
  let api_bind = if api_bind.trim().is_empty() {
    "127.0.0.1:8731".to_string()
  } else {
    api_bind
  };

  if api_bind.starts_with("0.0.0.0") && !unsafe_expose_api {
    return Err("unsafe_expose_api required for 0.0.0.0".into());
  }

  let needs_token = unsafe_expose_api || !is_localhost_bind(&api_bind);

  let mut guard = state.0.lock().unwrap();
  if guard.child.is_some() {
    return Err("daemon already running".into());
  }

  guard.last_error = None;
  guard.last_exit_code = None;
  guard.log_tail.clear();

  let app_dir = app
    .path()
    .app_data_dir()
    .map_err(|e| format!("app_data_dir error: {e}"))?
    .join("handshacke");
  std::fs::create_dir_all(&app_dir).map_err(|e| format!("mkdir error: {e}"))?;

  let token_file = app_dir.join("api.token");
  if needs_token && token_file.exists() {
    let _ = std::fs::remove_file(&token_file);
  }

  let mut cmd = app
    .shell()
    .sidecar("handshacke")
    .map_err(|e| format!("sidecar error: {e}"))?
    .env("HANDSHACKE_API_BIND", api_bind.as_str());

  let clean = |value: Option<String>| -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
  };

  if let Some(pt) = clean(pluggable_transport) {
    let pt = pt.to_lowercase();
    if pt != "none" {
      cmd = cmd.env("HANDSHACKE_PLUGGABLE_TRANSPORT", pt);
    }
  }

  if let Some(domain) = clean(realtls_domain) {
    cmd = cmd.env("HANDSHACKE_REALTLS_DOMAIN", domain);
  }

  if let Some(mode) = clean(stealth_mode) {
    cmd = cmd.env("HANDSHACKE_STEALTH_MODE", mode.to_lowercase());
  }

  if let Some(relays) = clean(assist_relays) {
    cmd = cmd.env("HANDSHACKE_ASSIST_RELAYS", relays);
  }

  if let Some(socks) = clean(tor_socks_addr) {
    cmd = cmd.env("HANDSHACKE_TOR_SOCKS", socks);
  }

  if let Some(onion) = clean(tor_onion_addr) {
    cmd = cmd.env("HANDSHACKE_TOR_ONION", onion);
  }

  if needs_token {
    cmd = cmd.env(
      "HANDSHACKE_API_TOKEN_FILE",
      token_file.to_string_lossy().to_string(),
    );
  }

  if unsafe_expose_api {
    cmd = cmd.arg("--unsafe-expose-api");
  }

  let (rx, child) = cmd.spawn().map_err(|e| format!("spawn error: {e}"))?;

  let pid = child.pid();

  guard.child = Some(child);
  guard.pid = Some(pid);
  guard.token_file = if needs_token { Some(token_file.clone()) } else { None };

  let app_handle = app.clone();
  tauri::async_runtime::spawn(async move {
    const MAX_LOG_LINES: usize = 200;
    let mut rx = rx;
    while let Some(event) = rx.recv().await {
      let state = app_handle.state::<DaemonState>();
      let mut guard = state.0.lock().unwrap();
      match event {
        CommandEvent::Stdout(bytes) => {
          for line in String::from_utf8_lossy(&bytes).lines() {
            if !line.trim().is_empty() {
              guard.log_tail.push_back(format!("[stdout] {line}"));
            }
          }
        }
        CommandEvent::Stderr(bytes) => {
          for line in String::from_utf8_lossy(&bytes).lines() {
            if !line.trim().is_empty() {
              guard.log_tail.push_back(format!("[stderr] {line}"));
            }
          }
        }
        CommandEvent::Error(err) => {
          guard.last_error = Some(format!("daemon error: {err}"));
        }
        CommandEvent::Terminated(payload) => {
          guard.pid = None;
          guard.child = None;
          guard.last_exit_code = payload.code;
          guard.last_error =
            Some(format!("daemon exited code={:?} signal={:?}", payload.code, payload.signal));
          break;
        }
        _ => {}
      }

      while guard.log_tail.len() > MAX_LOG_LINES {
        guard.log_tail.pop_front();
      }
    }
  });

  if needs_token {
    if let Err(err) = wait_for_token_file(&token_file, Duration::from_secs(5)) {
      guard.last_error = Some(format!("token file not ready: {err}"));
      if let Some(child) = guard.child.take() {
        let _ = child.kill();
      }
      guard.pid = None;
      guard.token_file = None;
      return Err(format!("token file not ready: {err}"));
    }
  }

  Ok(StartResult {
    pid,
    api_url: format!("http://{api_bind}"),
    token_file_path: if needs_token {
      token_file.to_string_lossy().to_string()
    } else {
      String::new()
    },
    token_required: needs_token,
  })
}

#[tauri::command]
async fn stop_daemon(state: State<'_, DaemonState>) -> Result<(), String> {
  let mut guard = state.0.lock().unwrap();
  if let Some(child) = guard.child.take() {
    let _ = child.kill();
  }
  if let Some(path) = guard.token_file.take() {
    let _ = std::fs::remove_file(path);
  }
  guard.pid = None;
  Ok(())
}

#[tauri::command]
async fn daemon_status(state: State<'_, DaemonState>) -> Result<StatusResult, String> {
  let guard = state.0.lock().unwrap();
  Ok(StatusResult {
    running: guard.child.is_some(),
    pid: guard.pid,
    last_error: guard.last_error.clone(),
    last_exit_code: guard.last_exit_code,
  })
}

#[tauri::command]
async fn daemon_logs(state: State<'_, DaemonState>) -> Result<Vec<String>, String> {
  let guard = state.0.lock().unwrap();
  Ok(guard.log_tail.iter().cloned().collect())
}

fn wait_for_token_file(path: &PathBuf, timeout: Duration) -> Result<(), String> {
  let start = std::time::Instant::now();
  while start.elapsed() < timeout {
    if let Ok(meta) = std::fs::metadata(path) {
      if meta.len() > 0 {
        #[cfg(windows)]
        {
          println!("Token file written (Windows: ensure directory ACLs are restricted)");
        }
        return Ok(());
      }
    }
    std::thread::sleep(Duration::from_millis(200));
  }
  Err("token file not ready".into())
}

fn is_localhost_bind(bind: &str) -> bool {
  if bind.starts_with("127.0.0.1") || bind.starts_with("localhost") {
    return true;
  }
  if bind.starts_with("[::1]") || bind.starts_with("::1") {
    return true;
  }
  if let Ok(addr) = bind.parse::<std::net::SocketAddr>() {
    return addr.ip().is_loopback();
  }
  false
}

fn main() {
  tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    .plugin(tauri_plugin_fs::init())
    .manage(DaemonState::default())
    .invoke_handler(tauri::generate_handler![
      start_daemon,
      stop_daemon,
      daemon_status,
      daemon_logs
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
