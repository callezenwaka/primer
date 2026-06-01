use colored::Colorize;

pub fn print_logo() {
    println!(
        "{}  {}",
        "primer".truecolor(53, 224, 161).bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
    println!();
}
