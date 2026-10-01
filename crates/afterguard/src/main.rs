//! afterguard CLI. `dispatch` owns the exit code so tests never call `run`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match afterguard::dispatch(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("afterguard: {err}");
            1
        }
    };
    std::process::exit(code);
}
