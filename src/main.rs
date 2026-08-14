fn main() {
    if let Err(e) = statelock::ui::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
