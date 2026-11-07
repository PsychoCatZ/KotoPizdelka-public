//! One process actor shared by Tauri and WorkManager. No headless WebView.
use jni::{
    objects::{GlobalRef, JClass, JObject, JValue},
    sys::{jboolean, jint, jlong},
    JNIEnv, JavaVM,
};
use messenger_app::{AppHandle, Reply, Request};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};

struct Bridge {
    vm: JavaVM,
    class: GlobalRef,
}
struct Runtime {
    actor: AppHandle,
    bridge: Arc<Bridge>,
    path: PathBuf,
    view: crate::notifications::NotificationView,
    gui_open: crate::profile_gate::ProfileGate,
    foreground: AtomicBool,
    focused: AtomicBool,
    cancelled: AtomicBool,
}
static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static GUI: OnceLock<tauri::AppHandle> = OnceLock::new();
pub fn attach_gui(app: tauri::AppHandle) {
    let _ = GUI.set(app);
}
fn publish_progress() {
    use tauri::Emitter;
    if let Some(app) = GUI.get() {
        let _ = app.emit_to("main", "profile-progress", ());
    }
}
static INITIALIZE: Mutex<()> = Mutex::new(());

impl Bridge {
    fn enabled(&self) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        let result = env.with_local_frame(8, |env| -> jni::errors::Result<bool> {
            let class = JClass::from(env.new_local_ref(self.class.as_obj())?);
            env.call_static_method(class, "backgroundEnabled", "()Z", &[])?
                .z()
        });
        let _ = env.exception_clear();
        result.unwrap_or(false)
    }

    fn notify(&self) {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            let _ = env.with_local_frame(16, |env| -> jni::errors::Result<()> {
                let class = JClass::from(env.new_local_ref(self.class.as_obj())?);
                env.call_static_method(class, "notifyIncoming", "(Z)V", &[JValue::Bool(0)])?;
                Ok(())
            });
            // Notification failure never propagates into the profile actor.
            let _ = env.exception_clear();
        }
    }
}
fn initialize(env: &mut JNIEnv<'_>, class: &JClass<'_>, context: &JObject<'_>) -> Result<(), ()> {
    let _guard = INITIALIZE.lock().map_err(|_| ())?;
    let file = env
        .call_method(context, "getDataDir", "()Ljava/io/File;", &[])
        .map_err(|_| ())?
        .l()
        .map_err(|_| ())?;
    let path = env
        .call_method(file, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .map_err(|_| ())?
        .l()
        .map_err(|_| ())?;
    let directory: String = env.get_string(&path.into()).map_err(|_| ())?.into();
    let path = PathBuf::from(directory).join("profile.sqlite");
    if let Some(runtime) = RUNTIME.get() {
        return if runtime.path == path {
            Ok(())
        } else {
            Err(())
        };
    }
    messenger_platform::initialize_android(env.get_java_vm().map_err(|_| ())?).map_err(|_| ())?;
    let bridge = Arc::new(Bridge {
        vm: env.get_java_vm().map_err(|_| ())?,
        class: env.new_global_ref(class).map_err(|_| ())?,
    });
    let (notifications, receiver) = std::sync::mpsc::sync_channel::<()>(1);
    let notifier = bridge.clone();
    std::thread::Builder::new()
        .name("messenger-notifications".into())
        .spawn(move || {
            while receiver.recv().is_ok() {
                notifier.notify();
            }
        })
        .map_err(|_| ())?;
    let actor = AppHandle::spawn_observed(path.clone(), false, move |contacts| {
        if let Some(runtime) = RUNTIME.get() {
            publish_progress();
            if !(runtime.focused.load(Ordering::Acquire) && runtime.view.all_viewed(&contacts)) {
                // One pending generic notification; no message data and no
                // blocking system callback on the database actor.
                let _ = notifications.try_send(());
            }
        }
    })
    .map_err(|_| ())?;
    RUNTIME
        .set(Runtime {
            actor,
            bridge,
            path,
            view: Default::default(),
            gui_open: Default::default(),
            foreground: AtomicBool::new(false),
            focused: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        })
        .map_err(|_| ())
}
pub fn actor(path: PathBuf) -> Result<AppHandle, &'static str> {
    RUNTIME
        .get()
        .filter(|r| r.path == path)
        .map(|r| r.actor.clone())
        .ok_or("Android runtime не готов.")
}
pub fn view(contact: Option<String>) -> Result<(), &'static str> {
    RUNTIME
        .get()
        .ok_or("Android runtime не готов.")?
        .view
        .set(contact)
}
pub async fn dispatch_gui(actor: &AppHandle, request: Request) -> Result<Reply, String> {
    let runtime = RUNTIME.get().ok_or("Android runtime не готов.")?;
    if let Some(reply) = runtime.gui_open.before(&request)? {
        return Ok(reply);
    }
    let opening = matches!(
        request,
        Request::OpenProfile | Request::RestoreProfile { .. }
    );
    let reply = actor.dispatch(request).await?;
    if opening {
        runtime.gui_open.finish_open(&reply);
    }
    Ok(reply)
}

#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_initialize(
    mut env: JNIEnv,
    class: JClass,
    context: JObject,
) -> jboolean {
    let result = initialize(&mut env, &class, &context).is_ok();
    let _ = env.exception_clear();
    result.into()
}
#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_presentation(
    _env: JNIEnv,
    _class: JClass,
    started: jboolean,
    focused: jboolean,
) {
    if let Some(r) = RUNTIME.get() {
        r.foreground.store(started != 0, Ordering::Release);
        r.focused
            .store(started != 0 && focused != 0, Ordering::Release);
        if started == 0 {
            let _ = r.view.set(None);
        }
    }
}
#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_hasProfile(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    RUNTIME
        .get()
        .is_some_and(|r| r.path.is_file() && messenger_platform::key_path(&r.path).is_file())
        .into()
}
#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_begin(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Some(r) = RUNTIME.get() {
        r.cancelled.store(false, Ordering::Release);
    }
}
#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_cancel(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Some(r) = RUNTIME.get() {
        r.cancelled.store(true, Ordering::Release);
    }
}
#[no_mangle]
pub extern "system" fn Java_ru_kotification_kotopizdelka_BackgroundBridge_sync(
    _env: JNIEnv,
    _class: JClass,
    cursor: jint,
) -> jlong {
    let Some(r) = RUNTIME.get() else {
        return 1;
    };
    // A background job never creates a profile or bypasses a missing key.
    if !r.path.is_file()
        || !messenger_platform::key_path(&r.path).is_file()
        || r.foreground.load(Ordering::Acquire)
    {
        return 2;
    }
    let Ok(executor) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return 1;
    };
    let start = cursor.max(0) as usize;
    let result = executor.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(110),
            r.actor.background_sync(start, || {
                r.cancelled.load(Ordering::Acquire)
                    || r.foreground.load(Ordering::Acquire)
                    || !r.bridge.enabled()
            }),
        )
        .await
    });
    match result {
        Ok(result) => {
            publish_progress();
            ((result.cursor as jlong) << 2) | jlong::from(result.retry)
        }
        Err(_) => ((start as jlong) << 2) | 1,
    }
}
