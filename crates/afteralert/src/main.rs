//! afteralert CLI.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = afteralert::dispatch(&args);
    std::process::exit(cveguard_proto::cli::finish("afteralert", &args, result));
}
