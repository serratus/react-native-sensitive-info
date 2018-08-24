import React, { Component } from 'react';
import { StyleSheet, Text, View, ActivityIndicator, Button, TextInput } from 'react-native';

const randomAlphabet = '0123456789ABCDEF'.split('');

const randomSignature = (length = 20) => {
  const signature = new Array(20);
  for (let i = 0; i < length; i++) {
    signature[i] = randomAlphabet[Math.floor(Math.random() * randomAlphabet.length)];
  }
  return signature.join('');
};

class Login extends Component {
  state = { error: '', loading: false, password: '' };

  _onLoginPress = () => {
    this.setState({
      loading: true
    });
    setTimeout(() => {
      this.setState((state) => {
        if (state.password === 'Password') {
          this.props.onSuccess(`234023984.28304283490.${randomSignature(12)}`);
          return {
            loading: false
          };
        }
        return {
          error: 'Password wrong',
          loading: false
        };
      });
    }, 1000);
  };

  _onChangeValue = (text) => {
    this.setState({
      password: text
    });
  };

  render() {
    const { loading, error } = this.state;
    return (
      <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center' }}>
        {!!error && <Text>{error}</Text>}
        <TextInput
          secureTextEntry
          onSubmitEditing={this._onLoginPress}
          placeholder="Password"
          style={{ width: 200 }}
          onChangeText={this._onChangeValue}
        />
        {loading ? <ActivityIndicator /> : <Button title="Login" onPress={this._onLoginPress} />}
      </View>
    );
  }
}

export default Login;
