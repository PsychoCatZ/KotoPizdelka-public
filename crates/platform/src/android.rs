//! Android-only AES-GCM wrapping through JNI and AndroidKeyStore.
//! Only an opaque nonce/ciphertext sidecar leaves the operating system boundary.

use crate::{Error, Result};

const IV_BYTES: usize = 12;
const WRAPPED_BYTES: usize = IV_BYTES + 32 + 16;

struct WrappedKey<'a> {
    iv: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_wrapped(blob: &[u8]) -> Result<WrappedKey<'_>> {
    if blob.len() != WRAPPED_BYTES {
        return Err(Error::InvalidKey);
    }
    let (iv, ciphertext) = blob.split_at(IV_BYTES);
    Ok(WrappedKey { iv, ciphertext })
}

#[cfg(target_os = "android")]
pub(crate) use native::{ensure_initialized, initialize, protect, unprotect};

#[cfg(target_os = "android")]
mod native {
    use super::{parse_wrapped, IV_BYTES, WRAPPED_BYTES};
    use crate::{Error, Result};
    use jni::{
        objects::{JByteArray, JObject, JValue},
        JNIEnv, JavaVM,
    };
    use messenger_core::StorageKey;
    use std::sync::OnceLock;
    use zeroize::Zeroizing;

    // The Android runtime has exactly one app-private profile. This alias is
    // scoped by Android to the application's UID, not a messaging identifier.
    const ALIAS: &str = "ru.kotification.kotopizdelka.storage-key.v1";
    const AAD: &[u8] = b"KotoPizdelka.storage-key.android-keystore.v1";
    static VM: OnceLock<JavaVM> = OnceLock::new();

    // Native errors are intentionally opaque: Java exception details must not
    // become UI responses, logs, paths, protected blobs or storage key data.
    impl From<jni::errors::Error> for Error {
        fn from(_: jni::errors::Error) -> Self {
            Self::ProtectionFailed
        }
    }

    pub(crate) fn initialize(vm: JavaVM) -> Result<()> {
        let pointer = vm.get_java_vm_pointer();
        match VM.set(vm) {
            Ok(()) => Ok(()),
            Err(_)
                if VM
                    .get()
                    .is_some_and(|vm| vm.get_java_vm_pointer() == pointer) =>
            {
                Ok(())
            }
            Err(_) => Err(Error::ProtectionFailed),
        }
    }

    pub(crate) fn ensure_initialized() -> Result<()> {
        VM.get().ok_or(Error::UnsupportedPlatform).map(|_| ())
    }

    fn with_env<T>(operation: impl FnOnce(&mut JNIEnv<'_>) -> Result<T>) -> Result<T> {
        let vm = VM.get().ok_or(Error::UnsupportedPlatform)?;
        let mut env = vm.attach_current_thread()?;
        // No JNIEnv or local object escapes this call. The worker's attachment
        // guard detaches it after both the local frame and exception cleanup.
        let result = env.with_local_frame(64, |env| {
            let result = operation(env);
            // A rejected cipher/provider call may leave a pending exception;
            // clear it without printing the exception or its message.
            env.exception_clear()?;
            result
        });
        // Also clear failures from local-frame allocation/pop themselves.
        env.exception_clear()?;
        result
    }

    fn key_store<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let provider = env.new_string("AndroidKeyStore")?;
        let store = env
            .call_static_method(
                "java/security/KeyStore",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[(&provider).into()],
            )?
            .l()?;
        env.call_method(
            &store,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[(&JObject::null()).into()],
        )?;
        Ok(store)
    }

    fn lookup_key<'a>(env: &mut JNIEnv<'a>, store: &JObject<'a>) -> Result<JObject<'a>> {
        let alias = env.new_string(ALIAS)?;
        let key = env
            .call_method(
                store,
                "getKey",
                "(Ljava/lang/String;[C)Ljava/security/Key;",
                &[(&alias).into(), (&JObject::null()).into()],
            )?
            .l()?;
        if key.is_null() || !env.is_instance_of(&key, "javax/crypto/SecretKey")? {
            return Err(Error::ProtectionFailed);
        }
        Ok(key)
    }

    fn create_key<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let alias = env.new_string(ALIAS)?;
        let builder = env.new_object(
            "android/security/keystore/KeyGenParameterSpec$Builder",
            "(Ljava/lang/String;I)V",
            &[(&alias).into(), JValue::Int(3)], // PURPOSE_ENCRYPT | PURPOSE_DECRYPT
        )?;
        for (method, value) in [
            ("setBlockModes", "GCM"),
            ("setEncryptionPaddings", "NoPadding"),
        ] {
            let value = env.new_string(value)?;
            let values = env.new_object_array(1, "java/lang/String", &value)?;
            env.call_method(
                &builder,
                method,
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[(&values).into()],
            )?;
        }
        env.call_method(
            &builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )?;
        env.call_method(
            &builder,
            "setRandomizedEncryptionRequired",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)],
        )?;
        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )?
            .l()?;
        let algorithm = env.new_string("AES")?;
        let provider = env.new_string("AndroidKeyStore")?;
        let generator = env
            .call_static_method(
                "javax/crypto/KeyGenerator",
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[(&algorithm).into(), (&provider).into()],
            )?
            .l()?;
        env.call_method(
            &generator,
            "init",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[(&spec).into()],
        )?;
        let key = env
            .call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?
            .l()?;
        if key.is_null() || !env.is_instance_of(&key, "javax/crypto/SecretKey")? {
            return Err(Error::ProtectionFailed);
        }
        Ok(key)
    }

    fn cipher<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>> {
        let transformation = env.new_string("AES/GCM/NoPadding")?;
        Ok(env
            .call_static_method(
                "javax/crypto/Cipher",
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[(&transformation).into()],
            )?
            .l()?)
    }

    fn add_aad(env: &mut JNIEnv<'_>, cipher: &JObject<'_>) -> Result<()> {
        let aad = env.byte_array_from_slice(AAD)?;
        env.call_method(cipher, "updateAAD", "([B)V", &[(&aad).into()])?;
        Ok(())
    }

    fn wipe_plaintext(env: &mut JNIEnv<'_>, plaintext: &JByteArray<'_>) -> Result<()> {
        // JNI cannot reliably mutate an array while an exception is pending.
        // Erase the input/output on both success and rejected cipher calls.
        env.exception_clear()?;
        let length = usize::try_from(env.get_array_length(plaintext)?)
            .map_err(|_| Error::ProtectionFailed)?;
        if length > 64 * 1024 {
            return Err(Error::ProtectionFailed);
        }
        let zeros = Zeroizing::new(vec![0i8; length]);
        env.set_byte_array_region(plaintext, 0, &zeros)?;
        Ok(())
    }

    pub(crate) fn protect(key: &StorageKey) -> Result<Vec<u8>> {
        with_env(|env| {
            let store = key_store(env)?;
            let alias = env.new_string(ALIAS)?;
            let exists = env
                .call_method(
                    &store,
                    "containsAlias",
                    "(Ljava/lang/String;)Z",
                    &[(&alias).into()],
                )?
                .z()?;
            // Called only after the locked file initializer proves there is no
            // database or sidecar. Existing aliases are reused, never replaced.
            let wrapping_key = if exists {
                lookup_key(env, &store)?
            } else {
                create_key(env)?
            };
            let cipher = cipher(env)?;
            env.call_method(
                &cipher,
                "init",
                "(ILjava/security/Key;)V",
                &[JValue::Int(1), (&wrapping_key).into()],
            )?;
            add_aad(env, &cipher)?;
            let plaintext = env.byte_array_from_slice(key.as_bytes())?;
            let result = (|| {
                let encrypted = JByteArray::from(
                    env.call_method(&cipher, "doFinal", "([B)[B", &[(&plaintext).into()])?
                        .l()?,
                );
                let iv = JByteArray::from(env.call_method(&cipher, "getIV", "()[B", &[])?.l()?);
                if env.get_array_length(&iv)? != IV_BYTES as i32
                    || env.get_array_length(&encrypted)? != (WRAPPED_BYTES - IV_BYTES) as i32
                {
                    return Err(Error::ProtectionFailed);
                }
                let mut blob = env.convert_byte_array(&iv)?;
                blob.extend_from_slice(&env.convert_byte_array(&encrypted)?);
                Ok(blob)
            })();
            let erased = wipe_plaintext(env, &plaintext);
            erased.and(result)
        })
    }

    pub(crate) fn unprotect(blob: &[u8]) -> Result<StorageKey> {
        // Reject malformed input before JNI, alias lookup, or any Keystore
        // operation. Unlocking NEVER takes the key-creation branch.
        let wrapped = parse_wrapped(blob)?;
        with_env(|env| {
            let store = key_store(env)?;
            let wrapping_key = lookup_key(env, &store)?;
            let cipher = cipher(env)?;
            let iv = env.byte_array_from_slice(wrapped.iv)?;
            let spec = env.new_object(
                "javax/crypto/spec/GCMParameterSpec",
                "(I[B)V",
                &[JValue::Int(128), (&iv).into()],
            )?;
            env.call_method(
                &cipher,
                "init",
                "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                &[JValue::Int(2), (&wrapping_key).into(), (&spec).into()],
            )?;
            add_aad(env, &cipher)?;
            let encrypted = env.byte_array_from_slice(wrapped.ciphertext)?;
            let plaintext = JByteArray::from(
                env.call_method(&cipher, "doFinal", "([B)[B", &[(&encrypted).into()])?
                    .l()?,
            );
            let result = (|| {
                if env.get_array_length(&plaintext)? != 32 {
                    return Err(Error::ProtectionFailed);
                }
                let bytes = Zeroizing::new(env.convert_byte_array(&plaintext)?);
                let mut key = Zeroizing::new([0; 32]);
                key.copy_from_slice(&bytes);
                Ok(StorageKey::from_bytes(*key))
            })();
            let erased = wipe_plaintext(env, &plaintext);
            erased.and(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_ciphertexts_are_rejected_before_any_native_operation() {
        for length in [0, 1, 12, 32, 59, 61, 64 * 1024] {
            assert!(matches!(
                parse_wrapped(&vec![0x7a; length]),
                Err(Error::InvalidKey)
            ));
        }
        let mut opaque = [0x4d; 60];
        opaque[..12].fill(0x28);
        let wrapped = parse_wrapped(&opaque).unwrap();
        assert_eq!(wrapped.iv, &[0x28; 12]);
        assert_eq!(wrapped.ciphertext, &[0x4d; 48]);
    }
}
