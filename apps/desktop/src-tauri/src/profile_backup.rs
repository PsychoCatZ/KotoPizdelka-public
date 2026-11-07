//! Native file picking and private opaque archive staging. No renderer-controlled paths.
use messenger_app::{AppHandle, Request};
use tauri::Manager;

#[cfg(target_os = "android")]
pub struct BackupFiles(pub tauri::plugin::PluginHandle<tauri::Wry>);
#[cfg(target_os = "android")]
pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("profile-backup")
        .setup(|app, api| {
            app.manage(BackupFiles(api.register_android_plugin(
                "ru.kotification.kotopizdelka",
                "ProfileBackupPlugin",
            )?));
            Ok(())
        })
        .build()
}
async fn send(app: &tauri::AppHandle, state: &AppHandle, request: Request) -> Result<(), String> {
    let _ = app;
    #[cfg(target_os = "android")]
    {
        crate::android_runtime::dispatch_gui(state, request).await?;
    }
    #[cfg(windows)]
    {
        let _ = app;
        state.dispatch(request).await?;
    }
    Ok(())
}
#[tauri::command]
pub async fn profile_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppHandle>,
    password: String,
    restore: bool,
    verify: bool,
) -> Result<bool, String> {
    if restore && verify {
        return Err("Выбери одну операцию.".into());
    }
    if !(12..=128).contains(&password.chars().count()) || password.len() > 512 {
        return Err("Пароль копии: от 12 до 128 символов.".into());
    }
    #[cfg(windows)]
    {
        let owner = app
            .get_webview_window("main")
            .ok_or("Окно недоступно.")?
            .hwnd()
            .map_err(|_| "Окно недоступно.")?
            .0 as isize;
        let selected = tauri::async_runtime::spawn_blocking(move || {
            messenger_platform::choose_backup_file(!(restore || verify), owner)
        })
        .await
        .map_err(|_| "Не удалось открыть выбор файла.")?
        .map_err(|_| "Не удалось открыть выбор файла.")?;
        let Some(path) = selected else {
            return Ok(false);
        };
        let request = if verify {
            Request::VerifyProfile { path, password }
        } else if restore {
            Request::RestoreProfile { path, password }
        } else {
            Request::ExportProfile { path, password }
        };
        send(&app, &state, request).await?;
        Ok(true)
    }
    #[cfg(target_os = "android")]
    {
        #[derive(serde::Serialize)]
        struct Save {
            path: String,
        }
        #[derive(serde::Deserialize)]
        struct Saved {
            done: bool,
        }
        #[derive(serde::Deserialize)]
        struct Opened {
            path: Option<String>,
        }
        let plugin = app.state::<BackupFiles>().0.clone();
        let folder = app
            .path()
            .app_cache_dir()
            .map_err(|_| "Хранилище недоступно.")?
            .join("profile-backups");
        std::fs::create_dir_all(&folder).map_err(|_| "Хранилище недоступно.")?;
        let folder = folder.canonicalize().map_err(|_| "Хранилище недоступно.")?;
        if restore || verify {
            let selected: Opened = plugin
                .run_mobile_plugin_async("open", ())
                .await
                .map_err(|_| "Не удалось прочитать файл копии.")?;
            let Some(selected) = selected.path else {
                return Ok(false);
            };
            let path = std::path::PathBuf::from(selected);
            if path.parent() != Some(folder.as_path())
                || !path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with("import-") && s.ends_with(".kotobackup"))
            {
                return Err("Недопустимый файл копии.".into());
            }
            let request = if verify {
                Request::VerifyProfile {
                    path: path.clone(),
                    password,
                }
            } else {
                Request::RestoreProfile {
                    path: path.clone(),
                    password,
                }
            };
            let result = send(&app, &state, request).await;
            let _ = std::fs::remove_file(path);
            result?;
            Ok(true)
        } else {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "Часы недоступны.")?
                .as_nanos();
            let path = folder.join(format!("export-{nonce}.kotobackup"));
            let result = async {
                send(
                    &app,
                    &state,
                    Request::ExportProfile {
                        path: path.clone(),
                        password,
                    },
                )
                .await?;
                let saved: Saved = plugin
                    .run_mobile_plugin_async(
                        "save",
                        Save {
                            path: path.to_string_lossy().into_owned(),
                        },
                    )
                    .await
                    .map_err(|_| "Не удалось сохранить файл копии.")?;
                Ok(saved.done)
            }
            .await;
            let _ = std::fs::remove_file(path);
            result
        }
    }
}
