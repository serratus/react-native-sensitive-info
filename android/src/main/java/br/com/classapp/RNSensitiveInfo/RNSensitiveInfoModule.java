package br.com.classapp.RNSensitiveInfo;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import br.com.classapp.RNSensitiveInfo.utils.AppConstants;
import br.com.classapp.RNSensitiveInfo.view.Fragments.FingerprintAuthenticationDialogFragment;
import br.com.classapp.RNSensitiveInfo.view.Fragments.FingerprintUiHelper;

public class RNSensitiveInfoModule extends ReactContextBaseJavaModule {

    // This must have 'AndroidKeyStore' as value. Unfortunately there is no predefined constant.
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

    // This is the default transformation used throughout this sample project.
    private static final String RSA_DEFAULT_TRANSFORMATION =
            KeyProperties.KEY_ALGORITHM_RSA + "/" +
                    KeyProperties.BLOCK_MODE_ECB + "/OAEPWithSHA-256AndMGF1Padding";

    private static final String KEY_ALIAS_RSA = "MyKeyPairTestAlias";

    private FingerprintManager mFingerprintManager;
    private KeyStore mKeyStore;
    private CancellationSignal mCancellationSignal;

    public RNSensitiveInfoModule(ReactApplicationContext reactContext) {
        super(reactContext);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprintManager = (FingerprintManager) reactContext.getSystemService(Context.FINGERPRINT_SERVICE);
            initKeyStore();
        }
    }

    @Override
    public String getName() {
        return "RNSensitiveInfo";
    }

    /**
     * Checks whether the device supports fingerprint authentication and if the user has
     * enrolled at least one fingerprint.
     *
     * @return true if the user has a fingerprint capable device and has enrolled
     * one or more fingerprints
     */
    private boolean hasSetupFingerprint() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && mFingerprintManager != null) {
                if (!mFingerprintManager.isHardwareDetected()) {
                    return false;
                } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
                    return false;
                }
                return true;
            } else {
                return false;
            }
        } catch (SecurityException e) {
            // Should never be thrown since we have declared the USE_FINGERPRINT permission
            // in the manifest file
            return false;
        }
    }

    @ReactMethod
    public void isHardwareDetected(final Promise pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pm.resolve(mFingerprintManager.isHardwareDetected());
        } else {
            pm.resolve(false);
        }
    }

    @ReactMethod
    public void hasEnrolledFingerprints(final Promise pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pm.resolve(mFingerprintManager.hasEnrolledFingerprints());
        } else {
            pm.resolve(false);
        }
    }

    @ReactMethod
    public void isSensorAvailable(final Promise promise) {
        promise.resolve(hasSetupFingerprint());
    }

    @ReactMethod
    public void getItem(String key, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        String value = prefs(name).getString(key, null);

        if (value != null && options.hasKey("touchID") && options.getBoolean("touchID")) {
            boolean showModal = options.hasKey("showModal") && options.getBoolean("showModal");
            HashMap strings = options.hasKey("strings") ? options.getMap("strings").toHashMap() : new HashMap();

            decryptWithRSA(value, showModal, strings, pm, null);
        } else {
            pm.resolve(value);
        }
    }

    @ReactMethod
    public void setItem(String key, String value, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        if (options.hasKey("touchID") && options.getBoolean("touchID")) {
            boolean showModal = options.hasKey("showModal") && options.getBoolean("showModal");
            HashMap strings = options.hasKey("strings") ? options.getMap("strings").toHashMap() : new HashMap();

            putExtraWithRSA(key, value, prefs(name), showModal, strings, pm, null);
        } else {
            try {
                putExtra(key, value, prefs(name));
                pm.resolve(value);
            } catch (Exception e) {
                Log.d("RNSensitiveInfo", e.getCause().getMessage());
                pm.reject(e);
            }
        }
    }


    @ReactMethod
    public void deleteItem(String key, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        SharedPreferences.Editor editor = prefs(name).edit();

        editor.remove(key).apply();

        pm.resolve(null);
    }


    @ReactMethod
    public void getAllItems(ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        Map<String, ?> allEntries = prefs(name).getAll();
        WritableMap resultData = new WritableNativeMap();

        for (Map.Entry<String, ?> entry : allEntries.entrySet()) {
            String value = entry.getValue().toString();
            resultData.putString(entry.getKey(), value);
        }
        pm.resolve(resultData);
    }

    @ReactMethod
    public void cancelFingerprintAuth() {
        if (mCancellationSignal != null && !mCancellationSignal.isCanceled()) {
            mCancellationSignal.cancel();
        }
    }

    private SharedPreferences prefs(String name) {
        return getReactApplicationContext().getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    @NonNull
    private String sharedPreferences(ReadableMap options) {
        String name = options.hasKey("sharedPreferencesName") ? options.getString("sharedPreferencesName") : "shared_preferences";
        if (name == null) {
            name = "shared_preferences";
        }
        return name;
    }


    private void putExtra(String key, Object value, SharedPreferences mSharedPreferences) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        if (value instanceof String) {
            editor.putString(key, (String) value).apply();
        } else if (value instanceof Boolean) {
            editor.putBoolean(key, (Boolean) value).apply();
        } else if (value instanceof Integer) {
            editor.putInt(key, (Integer) value).apply();
        } else if (value instanceof Long) {
            editor.putLong(key, (Long) value).apply();
        } else if (value instanceof Float) {
            editor.putFloat(key, (Float) value).apply();
        }
    }

    /**
     * Generates a new AES key and stores it under the { @code KEY_ALIAS_RSA } in the
     * Android Keystore.
     */
    private void initKeyStore() {
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
            mKeyStore.load(null);
        } catch (Exception e) {
        }
    }

    private void prepareKey(String alias) throws Exception {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M) {
            return;
        }
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_PROVIDER);
        keyGenerator.initialize(new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .setKeySize(2048)
                .build());
        keyGenerator.generateKeyPair();

    }

    private void initEncodeCipher(Cipher cipher, String alias) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
        PublicKey key = mKeyStore.getCertificate(alias).getPublicKey();
        PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(
                new X509EncodedKeySpec(key.getEncoded()));
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, unrestricted, spec);
    }


    // More information about this hack
    // from https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
    // from https://code.google.com/p/android/issues/detail?id=197719
    private Cipher getEncodeCipher(String alias) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_DEFAULT_TRANSFORMATION);
        if (!mKeyStore.containsAlias(alias)) {
            prepareKey(alias);
        }
        initEncodeCipher(cipher, alias);
        return cipher;
    }


    private void putExtraWithRSA(final String key, final String value, final SharedPreferences mSharedPreferences, final boolean showModal, final HashMap strings, final Promise pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M && hasSetupFingerprint()) {
            try {
                if (cipher == null) {
                    cipher = getEncodeCipher(KEY_ALIAS_RSA);
                    putExtraWithRSA(key, value, mSharedPreferences, showModal, strings, pm, cipher);
                    return;
                }
                byte[] encryptedBytes = cipher.doFinal(value.getBytes());
                String result = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
                putExtra(key, result, mSharedPreferences);
                pm.resolve(value);
            } catch (InvalidKeyException e) {
                pm.reject(e);
            } catch (SecurityException e) {
                pm.reject(e);
            } catch (Exception e) {
                pm.reject(e);
            }
        } else {
            pm.reject("Fingerprint not supported", "Fingerprint not supported");
        }
    }

    private void decryptWithRSA(final String encrypted, final boolean showModal, final HashMap strings, final Promise pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
                && hasSetupFingerprint()) {


            try {
                byte[] cipherBytes = Base64.decode(encrypted, Base64.DEFAULT);

                if (cipher == null) {
                    cipher = Cipher.getInstance(RSA_DEFAULT_TRANSFORMATION);
                    PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_ALIAS_RSA, null);
                    cipher.init(Cipher.DECRYPT_MODE, key);

                    KeyFactory factory = KeyFactory.getInstance(
                            key.getAlgorithm(), ANDROID_KEYSTORE_PROVIDER);
                    KeyInfo info = factory.getKeySpec(key, KeyInfo.class);

                    if (info.isUserAuthenticationRequired() &&
                            info.getUserAuthenticationValidityDurationSeconds() == -1) {

                        if (showModal) {

                            // define class as a callback
                            class DecryptWithAesCallback implements FingerprintUiHelper.Callback {
                                @Override
                                public void onAuthenticated(FingerprintManager.AuthenticationResult result) {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        decryptWithRSA(encrypted, showModal, strings, pm, result.getCryptoObject().getCipher());
                                    }
                                }

                                @Override
                                public void onError(String errorCode, CharSequence errString) {
                                    pm.reject(String.valueOf(errorCode), errString.toString());
                                }
                            }

                            // Show the fingerprint dialog
                            FingerprintAuthenticationDialogFragment fragment
                                    = FingerprintAuthenticationDialogFragment.newInstance(strings);
                            fragment.setCryptoObject(new FingerprintManager.CryptoObject(cipher));
                            fragment.setCallback(new DecryptWithAesCallback());

                            fragment.show(getCurrentActivity().getFragmentManager(), AppConstants.DIALOG_FRAGMENT_TAG);

                        } else {
                            mCancellationSignal = new CancellationSignal();
                            mFingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher), mCancellationSignal,
                                    0, new FingerprintManager.AuthenticationCallback() {

                                        @Override
                                        public void onAuthenticationFailed() {
                                            super.onAuthenticationFailed();
                                            getReactApplicationContext().getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                                                    .emit("FINGERPRINT_AUTHENTICATION_HELP", "Fingerprint not recognized.");
                                        }

                                        @Override
                                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                                            super.onAuthenticationError(errorCode, errString);
                                            pm.reject(String.valueOf(errorCode), errString.toString());
                                        }

                                        @Override
                                        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                            super.onAuthenticationHelp(helpCode, helpString);
                                            getReactApplicationContext().getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                                                    .emit("FINGERPRINT_AUTHENTICATION_HELP", helpString.toString());
                                        }

                                        @Override
                                        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                            super.onAuthenticationSucceeded(result);
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                                decryptWithRSA(encrypted, showModal, strings, pm, result.getCryptoObject().getCipher());
                                            }
                                        }
                                    }, null);
                        }
                    }
                    return;
                }
                byte[] decryptedBytes = cipher.doFinal(cipherBytes);
                pm.resolve(new String(decryptedBytes));
            } catch (InvalidKeyException e) {
                pm.reject(e);
            } catch (SecurityException e) {
                pm.reject(e);
            } catch (Exception e) {
                try {
                    mKeyStore.deleteEntry(KEY_ALIAS_RSA);
                    prepareKey(KEY_ALIAS_RSA);
                } catch (Exception e1) {
                    pm.reject(e1);
                    return;
                }
                pm.reject(e);
            }
        } else {
            pm.reject("Fingerprint not supported", "Fingerprint not supported");
        }
    }
}
