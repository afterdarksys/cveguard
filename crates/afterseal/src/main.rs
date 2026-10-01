//! afterseal CLI.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = afterseal::dispatch(&args);
    std::process::exit(cveguard_proto::cli::finish("afterseal", &args, result));
}
