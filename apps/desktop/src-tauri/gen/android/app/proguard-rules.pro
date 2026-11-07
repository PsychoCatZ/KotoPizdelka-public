# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# Headless JNI callbacks and worker class must keep their exact names.
-keep class ru.kotification.kotopizdelka.BackgroundBridge { *; }
-keep class ru.kotification.kotopizdelka.BackgroundSyncWorker {
  public <init>(android.content.Context, androidx.work.WorkerParameters);
  public *;
}

# Room instantiates WorkManager's generated database by reflection during
# AndroidX Startup, before MainActivity. Keep its zero-argument constructor
# as well as the class name; keeping the name alone lets R8 remove <init>().
-keep class androidx.work.impl.WorkDatabase_Impl {
  public <init>();
}

# Native file-picker plugin and reflectively parsed arguments.
-keep class ru.kotification.kotopizdelka.ProfileBackupPlugin { *; }
-keep class ru.kotification.kotopizdelka.BackupExportArgs { *; }
