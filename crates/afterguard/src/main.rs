//! afterguard CLI. `dispatch` owns the exit code so tests never call `run`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = afterguard::dispatch(&args);
    std::process::exit(cveguard_proto::cli::finish("afterguard", &args, result));
}
