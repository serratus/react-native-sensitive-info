import React from 'react';
import { Image, StyleSheet } from 'react-native';

const TouchImageSource = {
  uri:
    'data:image/png;base64,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'
};

export default props => <Image style={[styles.container, props.style]} source={TouchImageSource} />;

const styles = StyleSheet.create({
  container: { width: 50, height: 50 }
});
