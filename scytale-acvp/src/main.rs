//! Runs the ACVP protocol against a NIST server with the drivers in
//! the library crate, or replays a saved session, and shows the
//! implementation walk and the one-time code for debugging.

mod cli {
    use clap::{Parser, Subcommand};
    use scytale_acvp::profile::{Seed, walk};
    use scytale_acvp::replay::replay;
    use scytale_acvp::suite::{self, Suite, registrations};
    use scytale_acvp::support::Error;
    use scytale_acvp::totp;
    use std::path::PathBuf;
    use std::process::ExitCode;

    #[derive(Parser)]
    #[command(
        name = "scytale-acvp",
        about = "Runs NIST's ACVP vector sets against scytale",
        version
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Opens a test session on the server, answers every vector set
        /// and reports the verdicts.
        #[cfg(feature = "session")]
        Run {
            /// The server's base URL, up to and including /acvp/v1.
            #[arg(long, default_value = scytale_acvp::client::DEMO)]
            server: String,
            /// A sample session: the server also hands out its expected
            /// answers, which are checked before posting.
            #[arg(long)]
            sample: bool,
            /// Answers every vector set once per implementation this
            /// processor can run and insists they agree.
            #[arg(long)]
            every_kernel: bool,
            /// Only these suites, by directory name, algorithm or mode,
            /// comma separated.
            #[arg(long, value_delimiter = ',')]
            algorithms: Vec<String>,
            /// Writes every prompt, answer, expected answer and verdict
            /// here; by default to acvp-<session id> in the current
            /// directory. `resume` takes it up again.
            #[arg(long)]
            save: Option<PathBuf>,
            /// Draws the run's randomness from the operating system
            /// instead of the fixed seed.
            #[arg(long)]
            random_seed: bool,
            #[command(flatten)]
            credentials: Credentials,
        },
        /// Takes up the session a run saved: every vector set the
        /// server has not passed is answered again.
        #[cfg(feature = "session")]
        Resume {
            /// The directory a run saved to.
            dir: PathBuf,
            /// The server's base URL, up to and including /acvp/v1.
            #[arg(long, default_value = scytale_acvp::client::DEMO)]
            server: String,
            /// Only these suites; the other sets are left alone.
            #[arg(long, value_delimiter = ',')]
            algorithms: Vec<String>,
            #[arg(long)]
            every_kernel: bool,
            #[arg(long)]
            random_seed: bool,
            #[command(flatten)]
            credentials: Credentials,
        },
        /// The implementation walk for this processor.
        Profiles,
        /// The current one-time code, to check the seed and the clock.
        Totp {
            #[arg(long, env = "ACVP_TOTP_SEED", hide_env_values = true)]
            totp_seed: String,
        },
        /// Answers the prompts a run saved and compares them with the
        /// saved expected answers.
        Replay {
            dir: PathBuf,
            #[arg(long)]
            every_kernel: bool,
            #[arg(long)]
            random_seed: bool,
        },
        /// The registration that would be sent, as JSON.
        Registration {
            #[arg(long, value_delimiter = ',')]
            algorithms: Vec<String>,
        },
    }

    #[cfg(feature = "session")]
    #[derive(clap::Args)]
    struct Credentials {
        /// The client certificate, PEM.
        #[arg(long, env = "ACVP_CLIENT_CERT")]
        cert: String,
        /// Its private key, PEM.
        #[arg(long, env = "ACVP_CLIENT_KEY")]
        key: String,
        /// The TOTP seed, base64.
        #[arg(long, env = "ACVP_TOTP_SEED", hide_env_values = true)]
        totp_seed: String,
    }

    pub fn main() -> ExitCode {
        match run(Cli::parse()) {
            Ok(status) => ExitCode::from(status),
            Err(e) => {
                eprintln!("scytale-acvp: {e}");
                ExitCode::from(e.status as u8)
            }
        }
    }

    fn run(cli: Cli) -> Result<u8, Error> {
        match cli.command {
            #[cfg(feature = "session")]
            Command::Run {
                server,
                sample,
                every_kernel,
                algorithms,
                save,
                random_seed,
                credentials,
            } => {
                let suites = chosen(&algorithms)?;
                let registrations = registrations(&suites)?;
                let http = scytale_acvp::http::Http::try_new(
                    &credentials.cert,
                    &credentials.key,
                )?;
                let mut run = scytale_acvp::client::Run {
                    http,
                    base: server.trim_end_matches('/').to_string(),
                    totp_seed: credentials.totp_seed,
                    seed: seed(random_seed)?,
                    profiles: profiles(every_kernel),
                    save,
                    sample,
                    suites,
                };
                if registrations.is_empty() {
                    return Err(Error::new("nothing to register"));
                }
                let verdict = run.session(&registrations)?;
                Ok(report(&verdict))
            }
            #[cfg(feature = "session")]
            Command::Resume {
                dir,
                server,
                algorithms,
                every_kernel,
                random_seed,
                credentials,
            } => {
                let http = scytale_acvp::http::Http::try_new(
                    &credentials.cert,
                    &credentials.key,
                )?;
                let mut run = scytale_acvp::client::Run {
                    http,
                    base: server.trim_end_matches('/').to_string(),
                    totp_seed: credentials.totp_seed,
                    seed: seed(random_seed)?,
                    profiles: profiles(every_kernel),
                    save: Some(dir.clone()),
                    sample: false,
                    suites: chosen(&algorithms)?,
                };
                let verdict = run.resume(&dir)?;
                Ok(report(&verdict))
            }
            Command::Profiles => {
                let (runnable, refused) = walk();
                for p in runnable {
                    println!("{p}");
                }
                for p in refused {
                    println!("{p}: not on this processor");
                }
                Ok(0)
            }
            Command::Totp { totp_seed } => {
                println!("{}", totp::code(&totp_seed)?);
                Ok(0)
            }
            Command::Replay {
                dir,
                every_kernel,
                random_seed,
            } => {
                let problems =
                    replay(&dir, &seed(random_seed)?, &profiles(every_kernel))?;
                for p in &problems {
                    println!("{p}");
                }
                Ok(if problems.is_empty() { 0 } else { 1 })
            }
            Command::Registration { algorithms } => {
                let suites = chosen(&algorithms)?;
                let registrations = registrations(&suites)?;
                println!("{}", serde_json::to_string_pretty(&registrations)?);
                Ok(0)
            }
        }
    }

    /// Prints a session's verdict and gives the exit status.
    #[cfg(feature = "session")]
    fn report(verdict: &scytale_acvp::client::Verdict) -> u8 {
        println!(
            "session {}: {} passed, {} failed",
            verdict.session,
            verdict.passed,
            verdict.failed.len()
        );
        for why in &verdict.failed {
            println!("{why}");
        }
        if verdict.failed.is_empty() { 0 } else { 1 }
    }

    /// The suites named, or every suite.
    fn chosen(names: &[String]) -> Result<Vec<&'static Suite>, Error> {
        if names.is_empty() {
            return Ok(suite::SUITES.iter().collect());
        }
        let mut out = Vec::new();
        for name in names {
            let found = suite::find(name);
            if found.is_empty() {
                return Err(Error::new(format!("no suite named {name}")));
            }
            for s in found {
                if !out.iter().any(|o: &&Suite| std::ptr::eq(*o, s)) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    fn seed(random: bool) -> Result<Seed, Error> {
        if random {
            Seed::random()
        } else {
            Ok(Seed::fixed())
        }
    }

    fn profiles(every_kernel: bool) -> Vec<scytale::features::Features> {
        if every_kernel {
            let (runnable, refused) = walk();
            for p in refused {
                eprintln!("profile {p}: not on this processor, skipped");
            }
            runnable
        } else {
            vec![scytale::features::get()]
        }
    }
}

fn main() -> std::process::ExitCode {
    cli::main()
}
