use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use crypto_mac::{Mac, NewMac};
use hmac::Hmac;
use lazy_static::lazy_static;
use prettytable::{cell, row, Table};
use rand::{thread_rng, Rng};
use scrypt::{scrypt, ScryptParams};
use self_update::cargo_crate_version;
use serde::Deserialize;
use serde_derive::Serialize;
use sha1::Sha1;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use structopt::StructOpt;

fn rand_bytes(capacity: usize) -> Vec<u8> {
    let mut v = vec![0; capacity];
    thread_rng().fill(v.as_mut_slice());
    v
}

#[derive(Serialize, Deserialize, Debug)]
struct Account {
    name: String,
    digits: i8,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    key: Vec<u8>,
}

impl Account {
    fn gen(&self, counter: u64) -> Result<String> {
        let mut hmac = Hmac::<Sha1>::new_varkey(self.key.as_slice())
            .map_err(|_| anyhow!("invalid hmac key"))?;
        hmac.update(&counter.to_be_bytes());
        let code = hmac.finalize().into_bytes();
        let offset = (code[code.len() - 1] & 0xf) as usize;
        let code = u32::from_be_bytes(code[offset..offset + 4].try_into()?) & 0x7fff_ffff;
        let code = u64::from(code) % 10_u64.pow(self.digits.try_into()?);
        Ok(format!("{:06}", code))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Outer {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    passwd_salt: Vec<u8>,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    nonce: Vec<u8>,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    message: Vec<u8>,
}

fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|s| base64::decode(&s).map_err(|err| Error::custom(err.to_string())))
}

#[derive(StructOpt, Debug, Clone)]
enum Command {
    /// List codes.
    List,
    /// Add new account.
    Add,
    /// Remove an account.
    Rm,
    /// Change password.
    Passwd,
    /// List raw configuration.
    Raw,
    /// Update to new release.
    Update,
    /// Import data.
    Import { filename: String },
    /// Export data.
    Export { filename: String },
}

lazy_static! {
    static ref DEFAULT_FILE: PathBuf = dirs_next::home_dir().unwrap_or_default().join(".f2");
    static ref SCRYPT_PARAMS: ScryptParams =
        ScryptParams::new(20, 8, 1).expect("valid scrypt params");
}

#[derive(StructOpt, Debug)]
#[structopt(name = "f2")]
struct Args {
    /// File containing the data.
    #[structopt(short, long, default_value = DEFAULT_FILE.to_str().unwrap())]
    file: PathBuf,

    #[structopt(subcommand)]
    command: Option<Command>,
}

#[derive(Debug)]
struct App {
    file: PathBuf,
    passwd: Option<String>,
    accounts: Vec<Account>,
}

fn scrypt_key(passwd: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut key = vec![0; 32];
    scrypt(passwd, salt, &SCRYPT_PARAMS, &mut key)?;
    Ok(key)
}

enum Load {
    Required,
    Optional,
}

impl App {
    fn load(&mut self, mode: Load) -> Result<()> {
        let file = match File::open(&self.file) {
            Ok(file) => file,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    match mode {
                        Load::Optional => return Ok(()),
                        Load::Required => return Err(anyhow!("No data file found.")),
                    }
                } else {
                    return Err(err.into());
                }
            }
        };
        let reader = BufReader::new(file);
        let outer: Outer = serde_json::from_reader(reader)?;
        self.passwd = Some(rpassword::read_password_from_tty(Some("Password: "))?);
        let key = scrypt_key(
            self.passwd.as_ref().expect("password to be set").as_bytes(),
            &outer.passwd_salt,
        )?;
        let key = GenericArray::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&outer.nonce);
        let message = cipher
            .decrypt(nonce, outer.message.as_ref())
            .map_err(|_| anyhow!("Decryption failed: invalid password or corrupt file."))?;
        self.accounts = serde_json::from_slice(&message)?;
        Ok(())
    }

    fn ensure_passwd_for_add(&mut self) -> Result<()> {
        if self.passwd.is_none() {
            println!("Adding first account. Please configure your password.");
            println!("Use as long a password as possible.");
            let passwd = rpassword::read_password_from_tty(Some("New Password: "))?;
            let confirm = rpassword::read_password_from_tty(Some("Confirm Password: "))?;
            if passwd != confirm {
                return Err(anyhow!("Password do not match!"));
            }
            self.passwd = Some(passwd);
        }
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        self.accounts.sort_by(|a, b| a.name.cmp(&b.name));
        let passwd_salt = rand_bytes(24);
        let key = scrypt_key(
            self.passwd.as_ref().expect("password to be set").as_bytes(),
            &passwd_salt,
        )?;
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        let nonce = rand_bytes(12);
        let message = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                serde_json::to_vec(&self.accounts)?.as_ref(),
            )
            .map_err(|_| anyhow!("encryption failure"))?;
        let message = serde_json::to_vec(&Outer {
            passwd_salt,
            nonce,
            message,
        })?;
        File::create(&self.file)?.write_all(&message)?;
        Ok(())
    }

    fn command_list(&mut self) -> Result<()> {
        self.load(Load::Required)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        for a in &self.accounts {
            table.add_row(row![
                b->a.name,
                a.gen(now)?
            ]);
        }
        table.printstd();
        Ok(())
    }

    fn command_add(&mut self) -> Result<()> {
        self.load(Load::Optional)?;
        self.ensure_passwd_for_add()?;

        loop {
            let name = rprompt::prompt_reply_stdout("Name: ")?;
            if name.is_empty() {
                break;
            }
            let digits = {
                let digits = rprompt::prompt_reply_stdout("Digits (default 6): ")?;
                if digits.is_empty() {
                    6
                } else {
                    let digits = digits.parse()?;
                    if digits != 6 || digits != 7 || digits != 8 {
                        return Err(anyhow!("Invalid digits: must be one of 6, 7 or 8."));
                    }
                    digits
                }
            };
            let key = base32::decode(
                base32::Alphabet::RFC4648 { padding: false },
                &rprompt::prompt_reply_stdout("Key: ")?.to_ascii_uppercase(),
            )
            .ok_or_else(|| anyhow!("Invalid key: a valid key must be base32 encoded."))?;
            println!("Added {}.", name);
            self.accounts.push(Account { name, digits, key });
        }
        self.save()
    }

    fn command_rm(&mut self) -> Result<()> {
        self.load(Load::Required)?;
        let name = rprompt::prompt_reply_stdout("Name of account to remove: ")?;
        if name.is_empty() {
            return Ok(());
        }
        let index = self
            .accounts
            .iter()
            .position(|a| a.name == name)
            .ok_or_else(|| anyhow!("Account with given name was not found."))?;
        println!("Removed {}.", name);
        self.accounts.remove(index);
        self.save()
    }

    fn command_passwd(&mut self) -> Result<()> {
        self.load(Load::Required)?;
        let passwd = rpassword::read_password_from_tty(Some("New Password: "))?;
        let confirm = rpassword::read_password_from_tty(Some("Confirm Password: "))?;
        if passwd != confirm {
            return Err(anyhow!("Password do not match!"));
        }
        self.passwd = Some(passwd);
        self.save()
    }

    fn command_raw(&mut self) -> Result<()> {
        self.load(Load::Required)?;
        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        for a in &self.accounts {
            let key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &a.key);
            table.add_row(row![
                b->a.name,
                a.digits,
                key,
            ]);
        }
        table.printstd();
        Ok(())
    }

    fn command_import(&mut self, filename: &str) -> Result<()> {
        self.load(Load::Optional)?;
        self.ensure_passwd_for_add()?;
        let mut added = 0;
        let file = File::open(filename)?;
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file);
        for result in rdr.records() {
            let record = result?;
            let name = record[0].to_owned();
            let digits = record[1].parse()?;
            let key = base32::decode(
                base32::Alphabet::RFC4648 { padding: false },
                &record[2].to_ascii_uppercase(),
            )
            .ok_or_else(|| {
                anyhow!(
                    "Invalid key for {}: a valid key must be base32 encoded.",
                    name
                )
            })?;
            self.accounts.push(Account { name, digits, key });
            added += 1;
        }
        println!("Importing {} entries.", added);
        self.save()
    }

    fn command_export(&mut self, filename: &str) -> Result<()> {
        self.load(Load::Required)?;
        let file = File::create(filename)?;
        let mut wtr = csv::Writer::from_writer(file);
        for a in &self.accounts {
            let key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &a.key);
            wtr.write_record(&[&a.name, &format!("{}", a.digits), &key])?;
        }
        wtr.flush()?;
        Ok(())
    }

    fn command_update(&mut self) -> Result<()> {
        let status = self_update::backends::github::Update::configure()
            .repo_owner("daaku")
            .repo_name("f2")
            .bin_name("f2")
            .show_download_progress(true)
            .current_version(cargo_crate_version!())
            .build()?
            .update()?;
        if status.updated() {
            println!("Updated to {}.", status.version());
        } else {
            println!("Already up-to-date.");
        }
        Ok(())
    }

    fn run(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::List => self.command_list(),
            Command::Add => self.command_add(),
            Command::Rm => self.command_rm(),
            Command::Passwd => self.command_passwd(),
            Command::Raw => self.command_raw(),
            Command::Import { filename } => self.command_import(&filename),
            Command::Export { filename } => self.command_export(&filename),
            Command::Update => self.command_update(),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::from_args();
    App {
        file: args.file,
        passwd: None,
        accounts: vec![],
    }
    .run(args.command.unwrap_or(Command::List))
}
