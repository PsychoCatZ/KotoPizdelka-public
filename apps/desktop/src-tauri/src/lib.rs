#[cfg(target_os = "android")]
mod android_runtime;
#[cfg(any(windows, target_os = "android", test))]
mod notifications;
#[cfg(any(windows, target_os = "android"))]
mod profile_backup;
#[cfg(any(target_os = "android", test))]
mod profile_gate;

#[cfg(any(windows, target_os = "android", test))]
mod invitation_links;

#[cfg(any(windows, target_os = "android"))]
mod native {
    #[cfg(target_os = "android")]
    use crate::invitation_links::valid_link;
    use crate::invitation_links::PendingInvitation;
    use messenger_app::{AppHandle, Reply, Request};
    use tauri::{Emitter, Manager};
    use tauri_plugin_deep_link::DeepLinkExt;

    #[tauri::command]
    async fn dispatch(
        state: tauri::State<'_, AppHandle>,
        request: Request,
    ) -> Result<Reply, String> {
        #[cfg(target_os = "android")]
        {
            crate::android_runtime::dispatch_gui(&state, request).await
        }
        #[cfg(windows)]
        {
            state.dispatch(request).await
        }
    }

    #[tauri::command]
    fn take_pending_invitation(state: tauri::State<'_, PendingInvitation>) -> Option<String> {
        state.take()
    }

    fn publish_invitation(app: &tauri::AppHandle, link: &str) {
        if app.state::<PendingInvitation>().put(link) {
            // Only our local main WebView receives the opaque invitation. A
            // link never opens an external page or automatically accepts it.
            let _ = app.emit_to("main", "invitation-link", link);
        }
    }

    #[cfg(target_os = "android")]
    struct InvitationScanner(tauri::plugin::PluginHandle<tauri::Wry>);

    #[cfg(target_os = "android")]
    fn scanner_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
        tauri::plugin::Builder::new("invitation-scanner")
            .setup(|app, api| {
                let handle = api.register_android_plugin(
                    "ru.kotification.kotopizdelka",
                    "InvitationScannerPlugin",
                )?;
                app.manage(InvitationScanner(handle));
                Ok(())
            })
            .build()
    }

    #[tauri::command]
    async fn scan_invitation(app: tauri::AppHandle) -> Result<Option<String>, String> {
        #[cfg(target_os = "android")]
        {
            #[derive(serde::Deserialize)]
            struct ScanReply {
                link: Option<String>,
            }
            let scanner = app.state::<InvitationScanner>().0.clone();
            let result: ScanReply =
                scanner
                    .run_mobile_plugin_async("scan", ())
                    .await
                    .map_err(|_| {
                        "Не удалось прочитать QR-код. Можно вставить ссылку вручную.".to_owned()
                    })?;
            match result.link {
                Some(link) if valid_link(&link) => Ok(Some(link)),
                Some(_) => Err("Это не QR-код приглашения КотоПизделки.".to_owned()),
                None => Ok(None),
            }
        }
        #[cfg(windows)]
        {
            let _ = app;
            Err(
                "Сканирование камерой доступно на Android. Можно открыть ссылку или QR из файла."
                    .to_owned(),
            )
        }
    }

    #[cfg(target_os = "android")]
    struct LocalNotifications(tauri::plugin::PluginHandle<tauri::Wry>);
    #[cfg(target_os = "android")]
    fn notifications_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
        tauri::plugin::Builder::new("local-notifications")
            .setup(|app, api| {
                let handle = api.register_android_plugin(
                    "ru.kotification.kotopizdelka",
                    "LocalNotificationsPlugin",
                )?;
                app.manage(LocalNotifications(handle));
                Ok(())
            })
            .build()
    }
    #[tauri::command]
    async fn notification_settings(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            app.state::<LocalNotifications>()
                .0
                .clone()
                .run_mobile_plugin_async("settings", ())
                .await
                .map_err(|_| "Не удалось проверить настройки уведомлений.".into())
        }
        #[cfg(windows)]
        {
            let _ = app;
            Ok(serde_json::json!({"supported":false,"enabled":false,"allowed":false}))
        }
    }
    #[tauri::command]
    async fn set_notifications(
        app: tauri::AppHandle,
        enabled: bool,
    ) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            app.state::<LocalNotifications>()
                .0
                .clone()
                .run_mobile_plugin_async("configure", serde_json::json!({"enabled":enabled}))
                .await
                .map_err(|_| "Не удалось изменить настройку уведомлений.".into())
        }
        #[cfg(windows)]
        {
            let _ = (app, enabled);
            Ok(serde_json::json!({"supported":false,"enabled":false,"allowed":false}))
        }
    }
    #[tauri::command]
    async fn background_settings(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            app.state::<LocalNotifications>()
                .0
                .clone()
                .run_mobile_plugin_async("backgroundSettings", ())
                .await
                .map_err(|_| "Не удалось проверить фоновые настройки.".into())
        }
        #[cfg(windows)]
        {
            let _ = app;
            Ok(serde_json::json!({"supported":false,"enabled":false,"interval_minutes":15}))
        }
    }
    #[tauri::command]
    async fn set_background(
        app: tauri::AppHandle,
        enabled: bool,
    ) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            app.state::<LocalNotifications>()
                .0
                .clone()
                .run_mobile_plugin_async(
                    "configureBackground",
                    serde_json::json!({"enabled":enabled}),
                )
                .await
                .map_err(|_| "Не удалось изменить фоновое получение.".into())
        }
        #[cfg(windows)]
        {
            let _ = (app, enabled);
            Ok(serde_json::json!({"supported":false,"enabled":false,"interval_minutes":15}))
        }
    }

    #[tauri::command]
    fn notification_view(
        state: tauri::State<'_, crate::notifications::NotificationView>,
        contact: Option<String>,
    ) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let _ = state;
            crate::android_runtime::view(contact).map_err(str::to_owned)
        }
        #[cfg(windows)]
        {
            state.set(contact).map_err(str::to_owned)
        }
    }

    pub fn run() {
        let builder = tauri::Builder::default()
            .manage(PendingInvitation::default())
            .manage(crate::notifications::NotificationView::default());
        // Normal Windows launches share one profile and route a second link
        // launch into the existing process. Explicit local lab slots retain
        // their independent processes for the two-client test scenario.
        #[cfg(windows)]
        let builder = if std::env::var("KOTO_LOCAL_TEST").as_deref() == Ok("1") {
            builder
        } else {
            builder.plugin(tauri_plugin_single_instance::init(|app, args, _| {
                // The plugin normally forwards into DeepLink. During the
                // narrow startup window before that plugin is ready, retain
                // one strictly validated URI instead of dropping the launch.
                if app
                    .try_state::<tauri_plugin_deep_link::DeepLink<tauri::Wry>>()
                    .is_none()
                    && args.len() == 2
                {
                    publish_invitation(app, &args[1]);
                }
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }))
        };
        let builder = builder.plugin(tauri_plugin_deep_link::init());
        #[cfg(target_os = "android")]
        let builder = builder
            .plugin(scanner_plugin())
            .plugin(crate::profile_backup::plugin())
            .plugin(notifications_plugin());
        builder
            .setup(|app| {
                let handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        publish_invitation(&handle, url.as_str());
                    }
                });
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    for url in urls {
                        publish_invitation(app.handle(), url.as_str());
                    }
                }
                #[allow(unused_mut)]
                let mut directory = app.path().app_data_dir()?;
                // This process setting is solely for explicit loopback labs;
                // the renderer cannot enable insecure transport via IPC.
                #[cfg(windows)]
                let loopback = std::env::var("KOTO_LOCAL_TEST").as_deref() == Ok("1");
                #[cfg(windows)]
                if let Ok(slot) = std::env::var("KOTO_PROFILE_SLOT") {
                    if !loopback || !matches!(slot.as_str(), "demo-a" | "demo-b") {
                        return Err(std::io::Error::other("invalid local test profile").into());
                    }
                    directory = directory.join(slot);
                }
                std::fs::create_dir_all(&directory)?;
                #[cfg(windows)]
                let actor = AppHandle::spawn(directory.join("profile.sqlite"), loopback);
                #[cfg(target_os = "android")]
                let actor = crate::android_runtime::actor(directory.join("profile.sqlite"));
                let actor = actor.map_err(std::io::Error::other)?;
                app.manage(actor);
                #[cfg(target_os = "android")]
                crate::android_runtime::attach_gui(app.handle().clone());
                let configuration =
                    app.config().app.windows.first().ok_or_else(|| {
                        std::io::Error::other("main window configuration missing")
                    })?;
                let window = tauri::WebviewWindowBuilder::from_config(app, configuration)?
                    .on_navigation(|url| {
                        let app_origin = (url.scheme() == "tauri"
                            && url.host_str() == Some("localhost"))
                            || (url.scheme()
                                == if cfg!(target_os = "android") {
                                    "https"
                                } else {
                                    "http"
                                }
                                && url.host_str() == Some("tauri.localhost"));
                        let development = cfg!(all(windows, debug_assertions))
                            && url.scheme() == "http"
                            && url.host_str() == Some("127.0.0.1")
                            && url.port() == Some(1420);
                        app_origin || development || url.as_str() == "about:blank"
                    })
                    .build()?;
                let _ = window;
                #[cfg(windows)]
                {
                    use tauri::menu::{Menu, MenuItem};
                    use tauri::tray::{
                        MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent,
                    };
                    let open = MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?;
                    let exit = MenuItem::with_id(app, "exit", "Выйти", true, None::<&str>)?;
                    let menu = Menu::with_items(app, &[&open, &exit])?;
                    let show = |app: &tauri::AppHandle| {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    };
                    let mut tray = TrayIconBuilder::new()
                        .tooltip("КотоПизделка")
                        .menu(&menu)
                        .show_menu_on_left_click(false)
                        .on_menu_event(move |app, event| match event.id.as_ref() {
                            "open" => show(app),
                            "exit" => app.exit(0),
                            _ => {}
                        })
                        .on_tray_icon_event(move |tray, event| {
                            if matches!(
                                event,
                                TrayIconEvent::Click {
                                    button: MouseButton::Left,
                                    button_state: MouseButtonState::Up,
                                    ..
                                }
                            ) {
                                show(tray.app_handle());
                            }
                        });
                    if let Some(icon) = app.default_window_icon() {
                        tray = tray.icon(icon.clone());
                    }
                    // Do not intercept Close unless a tray was successfully
                    // installed: the user must always have a way to exit.
                    if tray.build(app).is_ok() {
                        let close_window = window.clone();
                        window.on_window_event(move |event| {
                            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                                if close_window.hide().is_ok() {
                                    api.prevent_close();
                                }
                            }
                        });
                    }
                }
                Ok(())
            })
            .invoke_handler(tauri::generate_handler![
                crate::profile_backup::profile_backup,
                dispatch,
                take_pending_invitation,
                scan_invitation,
                notification_settings,
                set_notifications,
                notification_view,
                background_settings,
                set_background
            ])
            .run(tauri::generate_context!())
            .expect("native runtime failed");
    }
}

#[cfg_attr(target_os = "android", tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(any(windows, target_os = "android"))]
    native::run();
    #[cfg(not(any(windows, target_os = "android")))]
    eprintln!("The native messenger runtime supports Windows and Android.");
}
