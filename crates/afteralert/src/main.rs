//! afteralert CLI. The accept loop lives in `dispatch` and is not used by tests.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match afteralert::dispatch(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("afteralert: {err}");
            1
        }
    };
    std::process::exit(code);
}
