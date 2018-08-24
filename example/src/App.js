import React, { Component } from 'react';
import { StyleSheet, AsyncStorage, Button, ActivityIndicator } from 'react-native';
import SInfo from 'react-native-sensitive-info';

import AuthProvider, { withAuth } from './AuthProvider';
import Settings from './Settings';
import Login from './Login';

const LogoutButton = withAuth(({ logout }) => <Button title="Logout" onPress={logout} />);

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      loading: true,
      settings: {
        touchEnabled: false
      }
    };
  }

  async componentDidMount() {
    try {
      const sensorAvailable = await SInfo.isSensorAvailable();
      const settings = await AsyncStorage.getItem('settings');
      console.log('Settings', settings);
      const state = {
        loading: false,
        ...(settings ? { settings: JSON.parse(settings) } : {})
      };
      this.setState({
        ...state,
        sensorAvailable,
        settings: {
          ...state.settings,
          touchEnabled: sensorAvailable && state.settings ? state.settings.touchEnabled : false
        }
      });
    } catch (e) {
      console.error(e);
    }
  }

  _handleChangeSettings = ({ touchEnabled }) => {
    this.setState(
      state => ({
        settings: {
          ...state.settings,
          touchEnabled
        }
      }),
      () => {
        AsyncStorage.setItem('settings', JSON.stringify(this.state.settings));
      }
    );
  };

  render() {
    const { loading, settings, sensorAvailable } = this.state;
    if (loading) {
      return <ActivityIndicator />;
    }
    return (
      <AuthProvider biometricEnabled={settings.touchEnabled} Login={Login}>
        <Settings
          settings={settings}
          sensorAvailable={sensorAvailable}
          onChangeSettings={this._handleChangeSettings}
        />
        <LogoutButton />
      </AuthProvider>
    );
  }
}

const styles = StyleSheet.create({});

export default App;
