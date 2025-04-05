use colored::*;
use diff::Result as DiffResult;
use git2::build::RepoBuilder;
use std::fs;
use std::io::{self, Write};
use tempfile::tempdir; // For colored output

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

// configuration parameters
const GIT_REPO_URL: &str = "https://github.com/NathanRignall/eris.git";
const FILE_PATH_IN_REPO: &str = "src/demo/test_hosts_override";

// On Windows, enable ANSI support so colored output works in the console.
#[cfg(windows)]
fn enable_ansi_support() {
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_OUTPUT_HANDLE;
    use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    unsafe {
        let std_out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(std_out_handle, &mut mode) != 0 {
            SetConsoleMode(std_out_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

// Fetch override content from a public git repository without credentials.
fn fetch_override_content(
    repo_url: &str,
    file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Clone the repository into a temporary directory.
    let tmp_dir = tempdir()?;
    let _repo = RepoBuilder::new().clone(repo_url, tmp_dir.path())?;

    // Read the override file from the cloned repository.
    let full_path = tmp_dir.path().join(file_path);
    let content = fs::read_to_string(full_path)?;
    Ok(content)
}

// Show a colored diff for just the override section and prompt for confirmation.
fn show_diff_and_confirm(old: &str, new: &str) -> io::Result<()> {
    println!("{}", format!("#---START-ERIS-CERT--OVERRIDE---").blue());
    for diff in diff::lines(old, new) {
        match diff {
            DiffResult::Left(l) => println!("{}", format!("- {}", l).red()),
            DiffResult::Right(r) => println!("{}", format!("+ {}", r).green()),
            DiffResult::Both(b, _) => println!("  {}", b),
        }
    }
    println!("{}", format!("#---END-ERIS-CERT--OVERRIDE---").blue());

    loop {
        print!("Do you want to apply these changes? [yes,no]: ");
        io::stdout().flush()?; // Ensure the prompt is printed
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "yes" => return Ok(()),
            "no" => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "User cancelled update",
                ))
            }
            _ => println!("Please enter 'yes' or 'no'."),
        }
    }
}

// Helper function to ask a yes/no question.
fn ask_yes_no(prompt: &str) -> io::Result<bool> {
    loop {
        print!("{} [yes,no]: ", prompt);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "yes" => return Ok(true),
            "no" => return Ok(false),
            _ => println!("Please enter 'yes' or 'no'."),
        }
    }
}

// Update the hosts file by inserting/replacing the custom override section.
fn update_hosts_file(new_section: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
    #[cfg(unix)]
    let hosts_path = "/etc/hosts";

    // Read the original hosts file content.
    let original_content = fs::read_to_string(hosts_path)?;

    let start_marker = "#---START-ERIS-CERT--OVERRIDE---";
    let end_marker = "#---END-ERIS-CERT--OVERRIDE---";

    // Extract the current override section (if it exists); otherwise, treat as empty.
    let old_override =
        if original_content.contains(start_marker) && original_content.contains(end_marker) {
            let start_index = original_content.find(start_marker).unwrap() + start_marker.len();
            let end_index = original_content.find(end_marker).unwrap();
            original_content[start_index..end_index].trim()
        } else {
            ""
        };

    // If the old override and new override are exactly the same, print a message and skip update.
    if old_override == new_section.trim() {
        println!("Contents of override section is unchanged. Skipping hosts file update.");
        return Ok(());
    }

    // Show colored diff for just the override section.
    show_diff_and_confirm(old_override, new_section)?;

    // Build new hosts file content.
    let new_content =
        if original_content.contains(start_marker) && original_content.contains(end_marker) {
            let start_index = original_content.find(start_marker).unwrap();
            let end_index = original_content.find(end_marker).unwrap() + end_marker.len();

            let mut content = String::new();
            content.push_str(&original_content[..start_index]);
            content.push_str(&format!("{}\n{}\n", start_marker, new_section));
            content.push_str(&format!("{}", end_marker));
            content.push_str(&original_content[end_index..]);
            content
        } else {
            let mut content = original_content.clone();
            content.push_str(&format!(
                "\n{}\n{}\n{}\n",
                start_marker, new_section, end_marker
            ));
            content
        };

    // Write the new content to the hosts file.
    fs::write(hosts_path, new_content)?;
    Ok(())
}

// On Windows, convert a string to a wide string (u16).
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// On Windows, add a certificate to the root store.
#[cfg(windows)]
fn add_certificate_to_root_store(cert_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::ptr;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::wincrypt::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore,
        CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        X509_ASN_ENCODING,
    };

    unsafe {
        let store_name_wide = to_wide("ROOT");
        let h_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            store_name_wide.as_ptr() as *const _,
        );
        if h_store.is_null() {
            return Err(format!("Failed to open certificate store: {}", GetLastError()).into());
        }

        let res = CertAddEncodedCertificateToStore(
            h_store,
            X509_ASN_ENCODING,
            cert_data.as_ptr(),
            cert_data.len() as DWORD,
            CERT_STORE_ADD_REPLACE_EXISTING,
            ptr::null_mut(),
        );
        if res == 0 {
            CertCloseStore(h_store, 0);
            return Err(format!("Failed to add certificate: {}", GetLastError()).into());
        }
        CertCloseStore(h_store, 0);
    }
    Ok(())
}

// Main logic wrapped in a run() function.
fn run(repo_url: &str, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch override content from the repository.
    let override_content = fetch_override_content(repo_url, file_path)?;

    // Update the hosts file with the new override section.
    update_hosts_file(&override_content)?;

    // Ask if the user wants to update the certificate.
    if ask_yes_no("Do you want to update the certificate?")? {
        #[cfg(windows)]
        {
            let cert_data: &[u8] = include_bytes!("demo/test_root_ca.cer");
            add_certificate_to_root_store(cert_data)?;
            println!("Certificate added to the root store successfully.");
        }
        #[cfg(unix)]
        {
            println!("Certificate update is not implemented for Unix systems.");
        }
    } else {
        println!("Certificate update skipped.");
    }

    Ok(())
}

// Main function that calls run() and waits for user input on exit.
fn main() {
    #[cfg(windows)]
    enable_ansi_support();

    // Run the main logic.
    let result = run(GIT_REPO_URL, FILE_PATH_IN_REPO);

    match result {
        Ok(_) => println!("Completed successfully."),
        Err(ref e) => eprintln!("Error: {}", e),
    }

    println!("Press enter to exit.");
    let mut exit_buffer = String::new();
    io::stdin().read_line(&mut exit_buffer).unwrap();
}
