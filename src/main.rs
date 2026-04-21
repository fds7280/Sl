mod ui; 
mod back;
mod enc;
mod vault;

fn main() {
    if let Err(e) = ui::init_tui() {
        eprintln!("Error initializing UI: {}", e);
    }


}
