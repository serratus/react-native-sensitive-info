import React, { Component } from 'react';
import PropTypes from 'prop-types';
import {
  StyleSheet,
  Text,
  View,
  Alert,
  Platform,
  AppState,
  DeviceEventEmitter,
  AsyncStorage,
  Button
} from 'react-native';
import SInfo from 'react-native-sensitive-info';

import FingerprintImage from './FingerprintImage';

class AuthProvider extends Component {
  static childContextTypes = {
    token: PropTypes.string,
    logout: PropTypes.func
  };

  constructor(props) {
    super(props);
    this.state = {
      locked: true,
      hint: '',
      showLogin: false,
      appState: AppState.currentState,
      error: null
    };
  }

  getChildContext() {
    return {
      token: this.state.token,
      logout: this._logout
    };
  }

  _logout = async () => {
    await Promise.all([AsyncStorage.removeItem('token'), SInfo.deleteItem('token', {})]);
    this.setState(
      {
        token: null
      },
      () => {
        this._showLockScreen();
      }
    );
  };

  async componentDidMount() {
    AppState.addEventListener('change', this._handleStateChange);
    DeviceEventEmitter.addListener('FINGERPRINT_AUTHENTICATION_HELP', this._handleAuthFeedback);
    this._showLockScreen();
  }

  _showLockScreen = async () => {
    console.log('_showLockScreen');
    const token = await this._loadToken();
    if (token) {
      console.log('_showLockScreen:withAuth');
      this.setState({
        locked: false,
        token
      });
    } else {
      console.log('_showLockScreen:noToken');
      this.setState((state) => {
        if (
          state.appState === 'active' ||
          (Platform.OS === 'ios' && state.appState === 'inactive')
        ) {
          return {
            showLogin: true,
            locked: true,
            token: null
          };
        }
      });
    }
  };

  _moveTokenToSecureStorage = async () => {
    const [header, body, signature] = this.state.token.split('.');
    await Promise.all([
      AsyncStorage.setItem('token', `${header}.${body}`),
      SInfo.setItem('token', signature, {
        touchID: true,
        keychainService: 'myKeychain2',
        kSecAccessControl: 'kSecAccessControlUserPresence',
        sharedPreferencesName: 'mySharedPrefs2',
        kSecAttrAccessible: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
        kSecUseOperationPrompt: 'Scan your fingerprint get the item.'
      })
    ]);
    console.log(`Token [${this.state.token}] moved to SecureStorage`);
  };

  _moveTokenToSharedStorage = async () => {
    await Promise.all([
      AsyncStorage.setItem('token', this.state.token),
      SInfo.deleteItem('token', {})
    ]);
    console.log(`Token [${this.state.token}] moved to SharedStorage`);
  };

  componentWillReceiveProps(nextProps) {
    if (nextProps.biometricEnabled && !this.props.biometricEnabled) {
      this._moveTokenToSecureStorage();
    } else if (!nextProps.biometricEnabled && this.props.biometricEnabled) {
      this._moveTokenToSharedStorage();
    }
  }

  componentWillUnmount() {
    AppState.removeEventListener('change', this._handleStateChange);
    SInfo.cancelFingerprintAuth();
    DeviceEventEmitter.removeListener('FINGERPRINT_AUTHENTICATION_HELP', this._handleAuthFeedback);
  }

  _prepareAuthentication = () => {
    if (Platform.OS === 'android') {
      this.setState({
        hint: 'Scan to Unlock'
      });
    }
  };

  _loadSecuredToken = () =>
    SInfo.getItem('token', {
      touchID: true,
      kSecUseOperationPrompt: 'Scan to Unlock.',
      keychainService: 'myKeychain2',
      kSecAccessControl: 'kSecAccessControlUserPresence',
      sharedPreferencesName: 'mySharedPrefs2',
      kSecAttrAccessible: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly'
    });

  _loadToken = async () => {
    const token = await AsyncStorage.getItem('token');
    if (token && this.props.biometricEnabled) {
      this._prepareAuthentication();
      try {
        console.log('_loadToken:biometric', token);
        const result = await this._loadSecuredToken();
        console.log('_loadToken:biometric:result', result);
        if (result) {
          return `${token}.${result}`;
        }
      } catch (err) {
        console.log('_loadToken:biometric:error', err);
      }
      return null;
    }
    return token;
  };

  _handleAuthFeedback = (helpText) => {
    this.setState({ hint: helpText });
  };

  _becameActive = nextAppState =>
    Platform.select({
      ios: this.state.appState.match(/background/) && nextAppState === 'active',
      android: this.state.appState.match(/inactive|background/) && nextAppState === 'active'
    });

  _transitionedToBackground = nextAppState =>
    this.state.appState.match(/inactive|active/) && nextAppState === 'background';

  _triggerLockScreen = () => {
    this.setState(
      {
        locked: true,
        hint: '',
        showLogin: false
      },
      () => {
        if (Platform.OS === 'android') {
          SInfo.cancelFingerprintAuth();
        }
      }
    );
  };

  _handleStateChange = (nextAppState) => {
    if (this._becameActive(nextAppState)) {
      this._showLockScreen();
    } else if (this._transitionedToBackground(nextAppState)) {
      this._triggerLockScreen();
    }
    console.log('_handleStateChange', nextAppState);
    this.setState({ appState: nextAppState });
  };

  _persistToken = (token) => {
    console.log('_persistToken', token);
    const { biometricEnabled } = this.props;
    if (biometricEnabled) {
      const [header, body, signature] = token.split('.');
      return Promise.all([
        SInfo.setItem('token', signature, {
          touchID: true,
          kSecUseOperationPrompt: 'Scan to Unlock.',
          keychainService: 'myKeychain2',
          kSecAccessControl: 'kSecAccessControlUserPresence',
          sharedPreferencesName: 'mySharedPrefs2',
          kSecAttrAccessible: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly'
        }),
        AsyncStorage.setItem('token', `${header}.${body}`)
      ])
        .catch((e) => {
          Alert.alert(err.message);
        })
        .then(() => {
          if (Platform.OS === 'android') {
            this.setState({
              helpText: ''
            });
          }
        });
    }
    console.log('biometric not enabled', token);
    return AsyncStorage.setItem('token', token);
  };

  _onLoginSuccess = async (token) => {
    console.log('_onLoginSuccess', token);
    await this._persistToken(token);
    console.log('_token persisted', token);
    this.setState({
      token,
      locked: false,
      showLogin: false
    });
  };

  _cancelTouch = () => {
    if (Platform.OS === 'android') {
      SInfo.cancelFingerprintAuth();
    }
  };

  render() {
    const { locked, showLogin, hint } = this.state;
    const { Login } = this.props;
    if (locked) {
      if (showLogin) {
        return <Login onSuccess={this._onLoginSuccess} />;
      }
      return (
        <View style={styles.container}>
          <Text>Lock Screen</Text>
          {Platform.select({
            android: (
              <View style={styles.touch}>
                <Text>{hint}</Text>
                <FingerprintImage />
                <Button title="Switch to Password" onPress={this._cancelTouch} />
              </View>
            )
          })}
        </View>
      );
    }
    return this.props.children;
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1
  },
  touch: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center'
  }
});

export const withAuth = Comp =>
  class WithAuth extends Component {
    static contextTypes = {
      token: PropTypes.string,
      logout: PropTypes.func
    };

    render() {
      const { token, logout } = this.context;
      return <Comp {...this.props} token={token} logout={logout} />;
    }
  };

export default AuthProvider;
