pub fn print_usage() {
    let terminal_width: u16 = 96;
    let mut output_width: usize = (terminal_width as f32 * 0.667) as usize;
    if output_width % 2 == 1 {
        if output_width < usize::MAX {
            output_width += 1;
        } else {
            output_width -= 1
        }
    }
    let section_size: usize = (output_width - 13) / 2;

    print_banner();
    println!("\x1b[0;94m{:=<output_width$}\x1b[0m", "");
    println!(
        "\x1b[0;94m{:=<section_size$} {} v{} {:=<section_size$}\x1b[0m",
        "",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        ""
    );
    println!("\x1b[0;94m{:=<output_width$}\x1b[0m", "");
    println!("{}", env!("CARGO_PKG_REPOSITORY"));

    // Todo Add a verbose output option switch
    // println!(
    //     "{}.{}.{}",
    //     env!("CARGO_PKG_VERSION_MAJOR"),
    //     env!("CARGO_PKG_VERSION_MINOR"),
    //     env!("CARGO_PKG_VERSION_PATCH")
    // )
}

fn print_banner() {
    print!("\n\x1b[0;95m");
    println!("     \x1b[0;95m███████      █████████   ███████████ ██████    ████████");
    println!("    \x1b[0;95m███\x1b[0;94m░░░░░\x1b[0;95m███   ███\x1b[0;94m░░░░░\x1b[0;95m███ \x1b[0;94m░░\x1b[0;95m███\x1b[0;94m░░░░░  ░░\x1b[0;95m███    ███\x1b[0;94m░░░░░\x1b[0;95m███");
    println!("   \x1b[0;95m███     \x1b[0;94m░░\x1b[0;95m███ \x1b[0;94m░\x1b[0;95m███    \x1b[0;94m░░░   ░\x1b[0;95m███   █    \x1b[0;94m░\x1b[0;95m███   ███     \x1b[0;94m░░░");
    println!("  \x1b[0;94m░\x1b[0;95m███      \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░\x1b[0;95m█████████   \x1b[0;94m░\x1b[0;95m███████    \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░\x1b[0;95m███");
    println!("  \x1b[0;94m░\x1b[0;95m███      \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░░░░░░░░\x1b[0;95m███  \x1b[0;94m░\x1b[0;95m███\x1b[0;94m░░░\x1b[0;95m█    \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░\x1b[0;95m███    █████");
    println!("  \x1b[0;94m░░\x1b[0;95m███     ███   ███    \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░\x1b[0;95m███  \x1b[0;94m░     ░\x1b[0;95m███  \x1b[0;94m░░\x1b[0;95m███  \x1b[0;94m░░\x1b[0;95m███");
    println!("   \x1b[0;94m░░\x1b[0;95m███████\x1b[0;94m░    ░\x1b[0;95m█████████   █████       ██████  \x1b[0;94m░░\x1b[0;95m████████");
    println!("     \x1b[0;94m░░░░░░░      ░░░░░░░░░   ░░░░░       ░░░░░░    ░░░░░░░░");
    print!("\x1b[0m");
}
