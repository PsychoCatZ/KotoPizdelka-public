fn main() {
    // Native clients use Windows DPAPI or Android Keystore. Linux tests of the
    // common actor do not require a graphical runtime.
    if matches!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("windows" | "android")
    ) {
        let attributes = tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "dispatch",
                "profile_backup",
                "take_pending_invitation",
                "scan_invitation",
                "notification_settings",
                "set_notifications",
                "notification_view",
                "background_settings",
                "set_background",
            ]),
        );
        tauri_build::try_build(attributes).expect("native build configuration failed");
    }
}
