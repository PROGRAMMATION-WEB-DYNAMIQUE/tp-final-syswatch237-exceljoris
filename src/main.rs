// ============================================================================
// SysWatch – Serveur TCP de surveillance système
// ============================================================================
// Étapes réalisées :
// 1. Modélisation des données (struct, Display)
// 2. Collecte réelle des métriques (sysinfo)
// 3. Formatage des réponses aux commandes
// 4. Serveur TCP multi‑threadé avec authentification
// 5. Journalisation des connexions et commandes (fichier syswatch.log)
// ============================================================================

use chrono::Local;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use sysinfo::System;

// Token d'authentification (à faire correspondre avec le client)
const AUTH_TOKEN: &str = "ENSPD2026";

// ----------------------------------------------------------------------------
// 1. Types métier
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CpuInfo {
    usage_percent: f32,
    core_count: usize,
}

#[derive(Debug, Clone)]
struct MemInfo {
    total_mb: u64,
    used_mb: u64,
    free_mb: u64,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cpu_usage: f32,
    memory_mb: u64,
}

#[derive(Debug, Clone)]
struct SystemSnapshot {
    timestamp: String,
    cpu: CpuInfo,
    memory: MemInfo,
    top_processes: Vec<ProcessInfo>,
}

// ----------------------------------------------------------------------------
// 2. Affichage (trait Display)
// ----------------------------------------------------------------------------

impl fmt::Display for CpuInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CPU: {:.1}% ({} coeurs)", self.usage_percent, self.core_count)
    }
}

impl fmt::Display for MemInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MEM: {}MB utilises / {}MB total ({} MB libres)",
            self.used_mb, self.total_mb, self.free_mb
        )
    }
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "  [{:>6}] {:<25} CPU:{:>5.1}%  MEM:{:>5}MB",
            self.pid, self.name, self.cpu_usage, self.memory_mb
        )
    }
}

impl fmt::Display for SystemSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== SysWatch - {} ===", self.timestamp)?;
        writeln!(f, "{}", self.cpu)?;
        writeln!(f, "{}", self.memory)?;
        writeln!(f, "--- Top Processus ---")?;
        for p in &self.top_processes {
            writeln!(f, "{}", p)?;
        }
        write!(f, "=====================")
    }
}

// ----------------------------------------------------------------------------
// 3. Collecte réelle des métriques (sysinfo)
// ----------------------------------------------------------------------------

fn collect_snapshot() -> Result<SystemSnapshot, String> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let core_count = sys.physical_core_count().unwrap_or(1);
    let cpu_usage = sys.global_cpu_info().cpu_usage();

    let total_mb = sys.total_memory() / 1_048_576;
    let used_mb = sys.used_memory() / 1_048_576;
    let free_mb = total_mb.saturating_sub(used_mb);

    let mut processes = Vec::new();
    for (pid, process) in sys.processes() {
        processes.push(ProcessInfo {
            pid: pid.as_u32(),
            name: process.name().to_string(),
            cpu_usage: process.cpu_usage(),
            memory_mb: process.memory() / 1_048_576,
        });
    }

    processes.sort_by(|a, b| b.cpu_usage.partial_cmp(&a.cpu_usage).unwrap());
    let top_processes = processes.into_iter().take(5).collect();

    Ok(SystemSnapshot {
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        cpu: CpuInfo {
            usage_percent: cpu_usage,
            core_count,
        },
        memory: MemInfo {
            total_mb,
            used_mb,
            free_mb,
        },
        top_processes,
    })
}

// ----------------------------------------------------------------------------
// 4. Formatage des réponses aux commandes client
// ----------------------------------------------------------------------------

fn format_response(snapshot: &SystemSnapshot, command: &str) -> String {
    match command.trim().to_lowercase().as_str() {
        "cpu" => format!("{}", snapshot.cpu),
        "mem" => format!("{}", snapshot.memory),
        "ps" => {
            let mut out = String::from("--- Top Processus ---\n");
            for p in &snapshot.top_processes {
                out.push_str(&format!("{}\n", p));
            }
            out
        }
        "all" => format!("{}", snapshot),
        "help" => {
            r#"Commandes disponibles:
  cpu  - Afficher l'utilisation CPU
  mem  - Afficher la memoire
  ps   - Afficher les 5 processus les plus actifs
  all  - Afficher toutes les informations
  help - Afficher cette aide
  quit - Quitter le client"#
                .to_string()
        }
        "quit" => "quit".to_string(),
        _ => format!(
            "Commande inconnue : {}\nTapez 'help' pour la liste.",
            command
        ),
    }
}

// ----------------------------------------------------------------------------
// 5. Journalisation (étape bonus) – version corrigée
// ----------------------------------------------------------------------------

fn log_event(event: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_line = format!("[{}] {}\n", timestamp, event);
    // On ouvre le fichier en mode append, on le crée s'il n'existe pas
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("syswatch.log")
    {
        let _ = file.write_all(log_line.as_bytes());
    }
}

// ----------------------------------------------------------------------------
// 6. Gestion d'un client (thread séparé)
// ----------------------------------------------------------------------------

fn handle_client(mut stream: TcpStream, snapshot: Arc<Mutex<SystemSnapshot>>) {
    let addr = stream.peer_addr().unwrap();
    let addr_str = addr.to_string();
    log_event(&format!("Connexion de {}", addr_str));
    println!("Nouveau client connecte : {}", addr_str);

    let mut reader = BufReader::new(&mut stream);

    // Étape d'authentification
    let _ = reader
        .get_mut()
        .write_all(b"Authentification requise. Envoyez le token : \n");
    let mut token = String::new();
    if reader.read_line(&mut token).is_err() {
        log_event(&format!("Echec lecture token de {}", addr_str));
        return;
    }
    if token.trim() != AUTH_TOKEN {
        let _ = reader
            .get_mut()
            .write_all(b"Token invalide. Connexion refusee.\n");
        log_event(&format!("Token invalide de {}", addr_str));
        println!("Token invalide de {}", addr_str);
        return;
    }
    let _ = reader
        .get_mut()
        .write_all(b"Authentifie. Commandes : cpu, mem, ps, all, help, quit\n");
    log_event(&format!("Authentification reussie pour {}", addr_str));

    // Boucle de traitement des commandes
    loop {
        let _ = reader.get_mut().write_all(b"> ");
        let mut command = String::new();
        if reader.read_line(&mut command).is_err() {
            break;
        }
        let cmd = command.trim();
        if cmd.is_empty() {
            continue;
        }

        log_event(&format!("Commande '{}' de {}", cmd, addr_str));

        if cmd == "quit" {
            let _ = reader.get_mut().write_all(b"Au revoir !\n");
            log_event(&format!("Deconnexion de {}", addr_str));
            break;
        }

        let snapshot_guard = snapshot.lock().unwrap();
        let response = format_response(&snapshot_guard, cmd);
        let _ = reader.get_mut().write_all(response.as_bytes());
        let _ = reader.get_mut().write_all(b"\n");
    }

    println!("Client deconnecte : {}", addr_str);
}

// ----------------------------------------------------------------------------
// 7. Programme principal : serveur TCP
// ----------------------------------------------------------------------------

fn main() -> std::io::Result<()> {
    // Snapshot initial (vide, sera écrasé rapidement)
    let initial_snapshot = SystemSnapshot {
        timestamp: String::new(),
        cpu: CpuInfo {
            usage_percent: 0.0,
            core_count: 0,
        },
        memory: MemInfo {
            total_mb: 0,
            used_mb: 0,
            free_mb: 0,
        },
        top_processes: vec![],
    };
    let snapshot = Arc::new(Mutex::new(initial_snapshot));

    // Thread de rafraîchissement toutes les 5 secondes
    let snapshot_refresher = Arc::clone(&snapshot);
    thread::spawn(move || loop {
        if let Ok(new_snapshot) = collect_snapshot() {
            let mut snap = snapshot_refresher.lock().unwrap();
            *snap = new_snapshot;
        }
        thread::sleep(Duration::from_secs(5));
    });

    // Démarrage du serveur
    let listener = TcpListener::bind("127.0.0.1:7878")?;
    println!("Serveur SysWatch demarre sur 127.0.0.1:7878");
    log_event("Serveur demarre");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let snapshot_clone = Arc::clone(&snapshot);
                thread::spawn(move || {
                    handle_client(stream, snapshot_clone);
                });
            }
            Err(e) => eprintln!("Erreur de connexion : {}", e),
        }
    }
    Ok(())
}