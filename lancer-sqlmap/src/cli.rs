//! clap-derived CLI. Every flag family from `## Granular feature catalog` in
//! the plan is represented here so the parser owns the full upstream surface.

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "lancer-sqlmap",
    version,
    about = "Rust clone of sqlmap — part of the Lancer bug bounty toolkit",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Force the CLI surface (default opens the native GUI window).
    #[arg(long, global = true)]
    pub cli: bool,

    /// Run the bundled self-test parity matrix.
    #[arg(long, global = true)]
    pub self_test: bool,

    /// List every supported DBMS short name.
    #[arg(long, global = true)]
    pub list_dbms: bool,

    /// List every built-in tamper script.
    #[arg(long, global = true)]
    pub list_tampers: bool,

    /// Verbosity (0-6) mapped to tracing levels.
    #[arg(short = 'v', long, default_value_t = 1, global = true)]
    pub verbosity: u8,

    /// Compact mnemonic options (e.g. `-z "bat,red,tor"`).
    #[arg(short = 'z', long, global = true)]
    pub mnemonics: Option<String>,

    /// Beep on found injection.
    #[arg(long, global = true)]
    pub beep: bool,

    /// Run command on alert (e.g. `xmessage`).
    #[arg(long, global = true)]
    pub alert: Option<String>,

    /// Pre-answer interactive prompts (e.g. `--answers='Y'`).
    #[arg(long, global = true)]
    pub answers: Option<String>,

    /// Output directory.
    #[arg(long, global = true, default_value = "lancer-sqlmap-out")]
    pub output_dir: PathBuf,

    /// Save current CLI invocation as a config file for replay.
    #[arg(long, global = true)]
    pub save: Option<PathBuf>,

    /// Path to a saved config file to load.
    #[arg(short = 'c', long, global = true)]
    pub config_file: Option<PathBuf>,

    /// Path to a session DB.
    #[arg(short = 's', long, global = true)]
    pub session_file: Option<PathBuf>,

    /// Traffic file (verbose request/response dump).
    #[arg(short = 't', long, global = true)]
    pub traffic_file: Option<PathBuf>,

    /// HAR-format request log.
    #[arg(long, global = true)]
    pub har: Option<PathBuf>,

    /// Non-interactive: accept all defaults.
    #[arg(long, global = true)]
    pub batch: bool,

    /// Interactive wizard.
    #[arg(long, global = true)]
    pub wizard: bool,

    /// Flush the session DB.
    #[arg(long, global = true)]
    pub flush_session: bool,

    /// Pull payloads fresh, ignoring any cached working state.
    #[arg(long, global = true)]
    pub fresh_queries: bool,

    /// Check internet connectivity before starting.
    #[arg(long, global = true)]
    pub check_internet: bool,

    /// Clean the target after a successful exploit (drop UDFs, etc.).
    #[arg(long, global = true)]
    pub cleanup: bool,

    /// Update the bundled tamper / payload registry from upstream mirror.
    #[arg(long, global = true)]
    pub update: bool,

    /// ──────────────────────────────────────────────────────────────────
    /// Target & request
    /// ──────────────────────────────────────────────────────────────────
    #[command(flatten)]
    pub target: TargetArgs,

    #[command(flatten)]
    pub request: RequestArgs,

    #[command(flatten)]
    pub optimization: OptimizationArgs,

    #[command(flatten)]
    pub injection: InjectionArgs,

    #[command(flatten)]
    pub detection: DetectionArgs,

    #[command(flatten)]
    pub techniques: TechniqueArgs,

    #[command(flatten)]
    pub fingerprint: FingerprintArgs,

    #[command(flatten)]
    pub enumeration: EnumerationArgs,

    #[command(flatten)]
    pub brute: BruteArgs,

    #[command(flatten)]
    pub udf: UdfArgs,

    #[command(flatten)]
    pub filesystem: FsArgs,

    #[command(flatten)]
    pub os_access: OsArgs,

    #[command(flatten)]
    pub registry: RegistryArgs,

    #[command(flatten)]
    pub general: GeneralArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Pivot from a Lancer scanner finding (auto-imports target, technique, params).
    Pivot {
        #[arg(long)]
        finding_id: String,
        #[arg(long)]
        tamper: Option<String>,
        #[arg(long)]
        batch: bool,
        #[arg(long)]
        dump: bool,
    },
    /// Interactive sql-shell against a known-working injection.
    SqlShell {
        #[arg(long)]
        session_file: Option<PathBuf>,
    },
    /// Interactive os-shell against a known-working injection.
    OsShell {
        #[arg(long)]
        session_file: Option<PathBuf>,
    },
    /// Run hashcracker against an extracted hash file.
    CrackHashes {
        #[arg(long)]
        hashes: PathBuf,
        #[arg(long)]
        wordlist: PathBuf,
    },
    /// Validate a payload yaml file (used by CI).
    ValidatePayloads {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Parser)]
pub struct TargetArgs {
    /// Target URL (e.g. https://target.com/vuln?id=1).
    #[arg(short = 'u', long)]
    pub url: Option<String>,

    /// Direct DB connect string (`mysql://user:pass@host/db`).
    #[arg(short = 'd', long)]
    pub direct: Option<String>,

    /// Burp / WebScarab log file with parsed requests.
    #[arg(short = 'l', long)]
    pub log: Option<PathBuf>,

    /// File containing multiple targets, one URL per line.
    #[arg(short = 'm', long)]
    pub targets: Option<PathBuf>,

    /// Raw HTTP request file (Burp style) — `*` marks injection point.
    #[arg(short = 'r', long)]
    pub request: Option<PathBuf>,

    /// Google dork target discovery.
    #[arg(short = 'g', long)]
    pub google_dork: Option<String>,
}

#[derive(Debug, Parser)]
pub struct RequestArgs {
    #[arg(long, default_value = "GET")]
    pub method: String,

    #[arg(long)]
    pub data: Option<String>,

    #[arg(long, default_value = "&")]
    pub param_del: String,

    #[arg(long)]
    pub cookie: Option<String>,

    #[arg(long, default_value = ";")]
    pub cookie_del: String,

    #[arg(long)]
    pub load_cookies: Option<PathBuf>,

    #[arg(long)]
    pub drop_set_cookie: bool,

    #[arg(long, alias = "ua")]
    pub user_agent: Option<String>,

    #[arg(long)]
    pub random_agent: bool,

    #[arg(long)]
    pub host: Option<String>,

    #[arg(long)]
    pub referer: Option<String>,

    #[arg(long, action = ArgAction::Append)]
    pub headers: Vec<String>,

    #[arg(long, value_enum)]
    pub auth_type: Option<AuthTypeArg>,

    #[arg(long)]
    pub auth_cred: Option<String>,

    #[arg(long)]
    pub auth_file: Option<PathBuf>,

    #[arg(long, action = ArgAction::Append)]
    pub ignore_code: Vec<u16>,

    #[arg(long)]
    pub ignore_proxy: bool,

    #[arg(long)]
    pub ignore_redirects: bool,

    #[arg(long)]
    pub ignore_timeouts: bool,

    #[arg(long)]
    pub proxy: Option<String>,

    #[arg(long)]
    pub proxy_cred: Option<String>,

    #[arg(long)]
    pub proxy_file: Option<PathBuf>,

    #[arg(long, default_value_t = 0)]
    pub proxy_freq: u32,

    #[arg(long)]
    pub tor: bool,

    #[arg(long, default_value_t = 9050)]
    pub tor_port: u16,

    #[arg(long, default_value = "SOCKS5")]
    pub tor_type: String,

    #[arg(long)]
    pub check_tor: bool,

    #[arg(long, default_value_t = 0)]
    pub delay: u64,

    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    #[arg(long, default_value_t = 3)]
    pub retries: u32,

    #[arg(long)]
    pub retry_on: Option<String>,

    #[arg(long)]
    pub randomize: Option<String>,

    #[arg(long)]
    pub safe_url: Option<String>,

    #[arg(long)]
    pub safe_post: Option<String>,

    #[arg(long)]
    pub safe_req: Option<PathBuf>,

    #[arg(long, default_value_t = 0)]
    pub safe_freq: u32,

    #[arg(long)]
    pub skip_urlencode: bool,

    #[arg(long)]
    pub csrf_token: Option<String>,

    #[arg(long)]
    pub csrf_url: Option<String>,

    #[arg(long)]
    pub csrf_method: Option<String>,

    #[arg(long)]
    pub csrf_data: Option<String>,

    #[arg(long, default_value_t = 0)]
    pub csrf_retries: u32,

    #[arg(long)]
    pub force_ssl: bool,

    #[arg(long)]
    pub chunked: bool,

    #[arg(long)]
    pub hpp: bool,

    #[arg(long)]
    pub eval: Option<String>,

    #[arg(long)]
    pub http2: bool,

    #[arg(long)]
    pub mfa_prompt: bool,
}

#[derive(Debug, Parser)]
pub struct OptimizationArgs {
    /// Enable all optimization flags.
    #[arg(short = 'o', long)]
    pub all_opts: bool,

    #[arg(long)]
    pub predict_output: bool,

    #[arg(long)]
    pub keep_alive: bool,

    #[arg(long)]
    pub null_connection: bool,

    #[arg(long, default_value_t = 1)]
    pub threads: u32,
}

#[derive(Debug, Parser)]
pub struct InjectionArgs {
    #[arg(short = 'p', long)]
    pub param: Option<String>,

    #[arg(long)]
    pub skip: Option<String>,

    #[arg(long)]
    pub skip_static: bool,

    #[arg(long)]
    pub param_exclude: Option<String>,

    #[arg(long)]
    pub param_filter: Option<String>,

    #[arg(long)]
    pub dbms: Option<String>,

    #[arg(long)]
    pub dbms_cred: Option<String>,

    #[arg(long)]
    pub os: Option<String>,

    #[arg(long)]
    pub invalid_bignum: bool,

    #[arg(long)]
    pub invalid_logical: bool,

    #[arg(long)]
    pub invalid_string: bool,

    #[arg(long)]
    pub no_cast: bool,

    #[arg(long)]
    pub no_escape: bool,

    #[arg(long)]
    pub prefix: Option<String>,

    #[arg(long)]
    pub suffix: Option<String>,

    #[arg(long)]
    pub tamper: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DetectionArgs {
    #[arg(long, default_value_t = 1)]
    pub level: u8,

    #[arg(long, default_value_t = 1)]
    pub risk: u8,

    #[arg(long)]
    pub string: Option<String>,

    #[arg(long)]
    pub not_string: Option<String>,

    #[arg(long)]
    pub regexp: Option<String>,

    #[arg(long)]
    pub code: Option<u16>,

    #[arg(long)]
    pub smart: bool,

    #[arg(long)]
    pub text_only: bool,

    #[arg(long)]
    pub titles: bool,
}

#[derive(Debug, Parser)]
pub struct TechniqueArgs {
    #[arg(long, default_value = "BEUSTQ")]
    pub technique: String,

    #[arg(long, default_value_t = 5)]
    pub time_sec: u32,

    #[arg(long, default_value = "1-10")]
    pub union_cols: String,

    #[arg(long, default_value = "NULL")]
    pub union_char: String,

    #[arg(long)]
    pub union_from: Option<String>,

    #[arg(long)]
    pub union_values: Option<String>,

    #[arg(long)]
    pub dns_domain: Option<String>,

    #[arg(long)]
    pub second_url: Option<String>,

    #[arg(long)]
    pub second_req: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct FingerprintArgs {
    #[arg(short = 'f', long)]
    pub fingerprint: bool,
}

#[derive(Debug, Parser)]
pub struct EnumerationArgs {
    #[arg(short = 'a', long)]
    pub all: bool,

    #[arg(short = 'b', long)]
    pub banner: bool,

    #[arg(long)]
    pub current_user: bool,

    #[arg(long)]
    pub current_db: bool,

    #[arg(long)]
    pub hostname: bool,

    #[arg(long)]
    pub is_dba: bool,

    #[arg(long)]
    pub users: bool,

    #[arg(long)]
    pub passwords: bool,

    #[arg(long)]
    pub privileges: bool,

    #[arg(long)]
    pub roles: bool,

    #[arg(long)]
    pub dbs: bool,

    #[arg(long)]
    pub tables: bool,

    #[arg(long)]
    pub columns: bool,

    #[arg(long)]
    pub schema: bool,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub dump: bool,

    #[arg(long)]
    pub dump_all: bool,

    #[arg(long)]
    pub search: Option<String>,

    #[arg(long)]
    pub comments: bool,

    #[arg(long)]
    pub statements: bool,

    #[arg(short = 'D', long)]
    pub db: Option<String>,

    #[arg(short = 'T', long)]
    pub table: Option<String>,

    #[arg(short = 'C', long)]
    pub cols: Option<String>,

    #[arg(short = 'X', long)]
    pub exclude_cols: Option<String>,

    #[arg(short = 'U', long)]
    pub user: Option<String>,

    #[arg(long)]
    pub exclude_sysdbs: bool,

    #[arg(long)]
    pub pivot_column: Option<String>,

    #[arg(long)]
    pub r#where: Option<String>,

    #[arg(long)]
    pub start: Option<usize>,

    #[arg(long)]
    pub stop: Option<usize>,

    #[arg(long)]
    pub first: Option<usize>,

    #[arg(long)]
    pub last: Option<usize>,

    #[arg(long)]
    pub sql_query: Option<String>,

    #[arg(long)]
    pub sql_shell: bool,

    #[arg(long)]
    pub sql_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct BruteArgs {
    #[arg(long)]
    pub common_tables: bool,
    #[arg(long)]
    pub common_columns: bool,
    #[arg(long)]
    pub common_files: bool,
}

#[derive(Debug, Parser)]
pub struct UdfArgs {
    #[arg(long)]
    pub udf_inject: bool,
    #[arg(long)]
    pub shared_lib: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct FsArgs {
    #[arg(long)]
    pub file_read: Option<String>,
    #[arg(long)]
    pub file_write: Option<PathBuf>,
    #[arg(long)]
    pub file_dest: Option<String>,
}

#[derive(Debug, Parser)]
pub struct OsArgs {
    #[arg(long)]
    pub os_cmd: Option<String>,
    #[arg(long)]
    pub os_shell: bool,
    #[arg(long)]
    pub os_pwn: bool,
    #[arg(long)]
    pub os_smbrelay: bool,
    #[arg(long)]
    pub os_bof: bool,
    #[arg(long)]
    pub priv_esc: bool,
    #[arg(long)]
    pub msf_path: Option<PathBuf>,
    #[arg(long)]
    pub tmp_path: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct RegistryArgs {
    #[arg(long)]
    pub reg_read: bool,
    #[arg(long)]
    pub reg_add: bool,
    #[arg(long)]
    pub reg_del: bool,
    #[arg(long)]
    pub reg_key: Option<String>,
    #[arg(long)]
    pub reg_value: Option<String>,
    #[arg(long)]
    pub reg_data: Option<String>,
    #[arg(long)]
    pub reg_type: Option<String>,
}

#[derive(Debug, Parser)]
pub struct GeneralArgs {
    #[arg(long)]
    pub binary_fields: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub crawl: u32,
    #[arg(long)]
    pub crawl_exclude: Option<String>,
    #[arg(long, default_value = ",")]
    pub csv_del: String,
    #[arg(long, default_value = "GBK")]
    pub charset: String,
    #[arg(long, value_enum, default_value_t = DumpFormatArg::Stdout)]
    pub dump_format: DumpFormatArg,
    #[arg(long, default_value = "utf-8")]
    pub encoding: String,
    #[arg(long)]
    pub eta: bool,
    #[arg(long)]
    pub forms: bool,
    #[arg(long)]
    pub hex: bool,
    #[arg(long)]
    pub parse_errors: bool,
    #[arg(long)]
    pub preprocess: Option<PathBuf>,
    #[arg(long)]
    pub postprocess: Option<PathBuf>,
    #[arg(long)]
    pub repair: bool,
    #[arg(long)]
    pub scope: Option<String>,
    #[arg(long)]
    pub test_filter: Option<String>,
    #[arg(long)]
    pub test_skip: Option<String>,
    #[arg(long)]
    pub gpage: Option<u32>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AuthTypeArg {
    Basic,
    Digest,
    Ntlm,
    Pki,
    Bearer,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum DumpFormatArg {
    Stdout,
    Csv,
    Html,
    Sqlite,
    Markdown,
    Json,
    Sarif,
}
