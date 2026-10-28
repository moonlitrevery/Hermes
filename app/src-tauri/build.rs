fn main() {
    // Rebuild when the baked-in Supabase settings change.
    println!("cargo:rerun-if-env-changed=HERMES_SUPABASE_URL");
    println!("cargo:rerun-if-env-changed=HERMES_SUPABASE_ANON_KEY");
    tauri_build::build()
}
