//! Lua-based runtime tampers — `--tamper=lua:my_tamper.lua`.
//!
//! Script contract:
//! ```lua
//! function tamper(payload)
//!   return payload:gsub(" ", "/**/")
//! end
//! return { name = "my", priority = 4, family = "space_replacer", apply = tamper }
//! ```
//!
//! `family` accepts the snake-case names of [`crate::TamperFamily`].

use crate::{Tamper, TamperError, TamperFamily};
use mlua::{Lua, Table};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;

pub struct LuaTamper {
    name: String,
    priority: u8,
    family: TamperFamily,
    terminal: bool,
    lua: Arc<Mutex<Lua>>,
    fn_key: String,
}

impl LuaTamper {
    pub fn load(path: impl AsRef<Path>) -> Result<Box<dyn Tamper>, TamperError> {
        let src = std::fs::read_to_string(&path)?;
        let lua = Lua::new();
        let tbl: Table = lua.load(&src).eval().map_err(|e| TamperError::Lua(e.to_string()))?;
        let name: String = tbl.get("name").map_err(|e| TamperError::Lua(e.to_string()))?;
        let priority: u8 = tbl.get("priority").unwrap_or(4);
        let family_s: String = tbl.get("family").unwrap_or_else(|_| "misc".into());
        let terminal: bool = tbl.get("terminal").unwrap_or(false);
        let family = parse_family(&family_s);

        // Stash the function in the registry so we can call it after Lua move.
        let f: mlua::Function = tbl.get("apply").map_err(|e| TamperError::Lua(e.to_string()))?;
        let key = format!("lua_tamper_{name}_{}", uuid::Uuid::new_v4());
        lua.set_named_registry_value(&key, f).map_err(|e| TamperError::Lua(e.to_string()))?;

        Ok(Box::new(LuaTamper {
            name: name.clone(),
            priority,
            family,
            terminal,
            lua: Arc::new(Mutex::new(lua)),
            fn_key: key,
        }))
    }
}

impl Tamper for LuaTamper {
    fn name(&self) -> &'static str {
        // We need a 'static — leak the string. Acceptable: tampers live for
        // the whole process.
        Box::leak(self.name.clone().into_boxed_str())
    }
    fn priority(&self) -> u8 { self.priority }
    fn family(&self) -> TamperFamily { self.family }
    fn is_terminal(&self) -> bool { self.terminal }
    fn apply(&self, payload: &str) -> String {
        let lua = self.lua.lock();
        let f: mlua::Function = match lua.named_registry_value(&self.fn_key) {
            Ok(f) => f,
            Err(_) => return payload.to_string(),
        };
        f.call::<String>(payload.to_string()).unwrap_or_else(|_| payload.to_string())
    }
}

fn parse_family(s: &str) -> TamperFamily {
    match s {
        "encoder" => TamperFamily::Encoder,
        "space_replacer" => TamperFamily::SpaceReplacer,
        "case_mutator" => TamperFamily::CaseMutator,
        "keyword_swapper" => TamperFamily::KeywordSwapper,
        "version_comment" => TamperFamily::VersionComment,
        "vendor" => TamperFamily::Vendor,
        "numeric" => TamperFamily::Numeric,
        "header" => TamperFamily::Header,
        _ => TamperFamily::Misc,
    }
}
