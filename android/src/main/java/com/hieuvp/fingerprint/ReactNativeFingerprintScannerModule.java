//Special

package com.hieuvp.fingerprint;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt.AuthenticationCallback;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.bridge.UiThreadUtil;

import com.facebook.react.modules.core.DeviceEventManagerModule.RCTDeviceEventEmitter;
import com.wei.android.lib.fingerprintidentify.FingerprintIdentify;
import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint.ExceptionListener;
import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint.IdentifyListener;


@ReactModule(name = "ReactNativeFingerprintScanner")
public class ReactNativeFingerprintScannerModule
        extends ReactContextBaseJavaModule
        implements LifecycleEventListener {

    public static final int MAX_AVAILABLE_TIMES = Integer.MAX_VALUE;
    public static final String TYPE_BIOMETRICS = "Biometrics";
    public static final String TYPE_FINGERPRINT_LEGACY = "Fingerprint";
    private static final String KEY_NAME = "biometric_key";
    private String custom = "";
    private final ReactApplicationContext mReactContext;
    private BiometricPrompt biometricPrompt;
    private FingerprintIdentify mFingerprintIdentify;

    public ReactNativeFingerprintScannerModule(ReactApplicationContext reactContext) {
        super(reactContext);
        mReactContext = reactContext;
    }

    @Override
    public String getName() {
        return "ReactNativeFingerprintScanner";
    }

    @Override
    public void onHostResume() {
    }

    @Override
    public void onHostPause() {
    }

    @Override
    public void onHostDestroy() {
        this.release();
    }

    private int currentAndroidVersion() {
        return Build.VERSION.SDK_INT;
    }

    private boolean requiresLegacyAuthentication() {
        return currentAndroidVersion() < 23;
    }

    public class AuthCallback extends BiometricPrompt.AuthenticationCallback {
        private Promise promise;

        public AuthCallback(final Promise promise) {
            this.promise = promise;
        }

        @Override
        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            this.promise.reject(biometricPromptErrName(errorCode), TYPE_BIOMETRICS);
        }

        @Override
        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
            byte[] encryptedInfo;
            BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
            try {

                Cipher cipher = cryptoObject.getCipher();
                encryptedInfo = cipher.doFinal(custom.getBytes(StandardCharsets.UTF_8));

                WritableMap map = Arguments.createMap();
                map.putBoolean("success", true);
                map.putString("custom", new String(encryptedInfo, StandardCharsets.UTF_8));
                this.promise.resolve(map);

            } catch (Exception ignored) {
                this.promise.reject(biometricPromptErrName(0), TYPE_BIOMETRICS);
            }


        }
    }

    public BiometricPrompt getBiometricPrompt(final FragmentActivity fragmentActivity, final Promise promise) {
        if (biometricPrompt != null) return biometricPrompt;

        mReactContext.addLifecycleEventListener(this);

        AuthCallback authCallback = new AuthCallback(promise);
        Executor executor = Executors.newSingleThreadExecutor();
        biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

        return biometricPrompt;
    }


    private void createKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            KeyGenParameterSpec.Builder keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setUserAuthenticationRequired(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                keyGenParameterSpec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
            }


            keyGenerator.init(keyGenParameterSpec.build());
            keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private Cipher getCipher() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);

            Cipher cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/" +
                            KeyProperties.BLOCK_MODE_CBC + "/" +
                            KeyProperties.ENCRYPTION_PADDING_PKCS7);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void biometricAuthenticate(final String title, final String subtitle, final String description, final String cancelButton, final Promise promise) {
        UiThreadUtil.runOnUiThread(() -> {
            FragmentActivity fragmentActivity = (FragmentActivity) mReactContext.getCurrentActivity();
            if (fragmentActivity == null) return;

            BiometricPrompt bioPrompt = getBiometricPrompt(fragmentActivity, promise);

            PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .setDeviceCredentialAllowed(false)
                    .setConfirmationRequired(false)
                    .setNegativeButtonText(cancelButton)
                    .setDescription(description)
                    .setSubtitle(subtitle)
                    .setTitle(title)
                    .build();

            createKey();
            Cipher cipher = getCipher();

            if (cipher == null) {
                promise.reject("CryptoInitFailed", "Cipher is null or failed to initialize.");
                return;
            }

            BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
            bioPrompt.authenticate(promptInfo, cryptoObject);
        });
    }

    private String biometricPromptErrName(int errCode) {
        switch (errCode) {
            case BiometricPrompt.ERROR_CANCELED:
                return "SystemCancel";
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
                return "FingerprintScannerNotSupported";
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
                return "FingerprintScannerNotAvailable";
            case BiometricPrompt.ERROR_LOCKOUT:
                return "DeviceLocked";
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return "DeviceLockedPermanent";
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                return "UserCancel";
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return "FingerprintScannerNotEnrolled";
            case BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL:
                return "PasscodeNotSet";
            case BiometricPrompt.ERROR_NO_SPACE:
                return "DeviceOutOfMemory";
            case BiometricPrompt.ERROR_TIMEOUT:
                return "AuthenticationTimeout";
            case BiometricPrompt.ERROR_UNABLE_TO_PROCESS:
                return "AuthenticationProcessFailed";
            case BiometricPrompt.ERROR_USER_CANCELED:
                return "UserFallback";
            case BiometricPrompt.ERROR_VENDOR:
                return "HardwareError";
            default:
                return "FingerprintScannerUnknownError";
        }
    }

    private String getSensorError() {
        BiometricManager biometricManager = BiometricManager.from(mReactContext);
        int authResult = biometricManager.canAuthenticate();

        switch (authResult) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return null;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return "FingerprintScannerNotSupported";
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return "FingerprintScannerNotEnrolled";
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return "FingerprintScannerNotAvailable";
            default:
                return null;
        }
    }

    @ReactMethod
    public void authenticate(String title, String subtitle, String description, String cancelButton, String custom, final Promise promise) {
        if (requiresLegacyAuthentication()) {
            legacyAuthenticate(promise);
        } else {
            final String errorName = getSensorError();
            if (errorName != null) {
                promise.reject(errorName, TYPE_BIOMETRICS);
                release();
                return;
            }

            if (custom != null) {
                this.custom = custom;
            }

            biometricAuthenticate(title, subtitle, description, cancelButton, promise);
        }
    }

    @ReactMethod
    public void release() {
        if (requiresLegacyAuthentication()) {
            if (mFingerprintIdentify != null) {
                mFingerprintIdentify.cancelIdentify();
                mFingerprintIdentify = null;
            }
        }

        if (biometricPrompt != null) {
            biometricPrompt.cancelAuthentication();
        }
        biometricPrompt = null;
        mReactContext.removeLifecycleEventListener(this);
    }

    @ReactMethod
    public void isSensorAvailable(final Promise promise) {
        if (requiresLegacyAuthentication()) {
            String errorMessage = legacyGetErrorMessage();
            if (errorMessage != null) {
                promise.reject(errorMessage, TYPE_FINGERPRINT_LEGACY);
            } else {
                promise.resolve(TYPE_FINGERPRINT_LEGACY);
            }
            return;
        }

        String errorName = getSensorError();
        if (errorName != null) {
            promise.reject(errorName, TYPE_BIOMETRICS);
        } else {
            promise.resolve(TYPE_BIOMETRICS);
        }
    }

    private FingerprintIdentify getFingerprintIdentify() {
        if (mFingerprintIdentify != null) return mFingerprintIdentify;

        mReactContext.addLifecycleEventListener(this);
        mFingerprintIdentify = new FingerprintIdentify(mReactContext);
        mFingerprintIdentify.setSupportAndroidL(true);
        mFingerprintIdentify.setExceptionListener(
                exception -> mReactContext.removeLifecycleEventListener(ReactNativeFingerprintScannerModule.this)
        );
        mFingerprintIdentify.init();
        return mFingerprintIdentify;
    }

    private String legacyGetErrorMessage() {
        if (!getFingerprintIdentify().isHardwareEnable()) return "FingerprintScannerNotSupported";
        if (!getFingerprintIdentify().isRegisteredFingerprint())
            return "FingerprintScannerNotEnrolled";
        if (!getFingerprintIdentify().isFingerprintEnable())
            return "FingerprintScannerNotAvailable";
        return null;
    }

    private void legacyAuthenticate(final Promise promise) {
        final String errorMessage = legacyGetErrorMessage();
        if (errorMessage != null) {
            promise.reject(errorMessage, TYPE_FINGERPRINT_LEGACY);
            release();
            return;
        }

        getFingerprintIdentify().resumeIdentify();
        getFingerprintIdentify().startIdentify(MAX_AVAILABLE_TIMES, new IdentifyListener() {
            @Override
            public void onSucceed() {
                promise.resolve(true);
            }

            @Override
            public void onNotMatch(int availableTimes) {
                String msg = (availableTimes <= 0) ? "DeviceLocked" : "AuthenticationNotMatch";
                mReactContext.getJSModule(RCTDeviceEventEmitter.class)
                        .emit("FINGERPRINT_SCANNER_AUTHENTICATION", msg);
            }

            @Override
            public void onFailed(boolean isDeviceLocked) {
                promise.reject("AuthenticationFailed", isDeviceLocked ? "DeviceLocked" : TYPE_FINGERPRINT_LEGACY);
                release();
            }

            @Override
            public void onStartFailedByDeviceLocked() {
                promise.reject("AuthenticationFailed", "DeviceLocked");
            }
        });
    }
}