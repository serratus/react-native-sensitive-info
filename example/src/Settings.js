import React from 'react';
import { StyleSheet, Text, View, Switch } from 'react-native';

import { withAuth } from './AuthProvider';

const Settings = withAuth(({ token, settings, onChangeSettings, sensorAvailable }) => (
  <View style={styles.container}>
    <Text>Token: {token}</Text>
    <View style={styles.setting}>
      <Text>TouchID/Passcode</Text>
      <Switch
        disabled={!sensorAvailable}
        value={settings.touchEnabled}
        onValueChange={enabled => onChangeSettings({ touchEnabled: enabled })}
      />
    </View>
  </View>
));

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    backgroundColor: '#F5FCFF'
  },
  setting: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  }
});

export default Settings;
