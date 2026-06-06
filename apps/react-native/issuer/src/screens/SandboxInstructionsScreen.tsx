// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
} from 'react-native';
// AsyncStorage is appropriate for non-sensitive UI preferences like sandbox mode confirmation
import AsyncStorage from '@react-native-async-storage/async-storage';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import type {RootStackParamList} from '../../App';

type Props = NativeStackScreenProps<RootStackParamList, 'SandboxInstructions'>;

const SANDBOX_CONFIRMED_KEY = 'sandbox_mode_confirmed';

export default function SandboxInstructionsScreen({
  navigation,
}: Props): React.JSX.Element {
  const handleConfirm = async () => {
    try {
      await AsyncStorage.setItem(SANDBOX_CONFIRMED_KEY, 'true');
      navigation.replace('AgeSelection');
    } catch (error) {
      if (__DEV__) {
        console.error('Failed to save sandbox confirmation:', error);
      }
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Sandbox Mode Required</Text>

        <Text style={styles.description}>
          Before using this demo app, you need to enable sandbox mode in the
          Provii Wallet app.
        </Text>

        <View style={styles.instructionsContainer}>
          <Text style={styles.instructionsTitle}>Instructions:</Text>

          <View style={styles.step}>
            <Text style={styles.stepNumber}>1.</Text>
            <Text style={styles.stepText}>Open the Provii Wallet app</Text>
          </View>

          <View style={styles.step}>
            <Text style={styles.stepNumber}>2.</Text>
            <Text style={styles.stepText}>Go to Settings</Text>
          </View>

          <View style={styles.step}>
            <Text style={styles.stepNumber}>3.</Text>
            <Text style={styles.stepText}>
              Tap the Settings header 5 times to reveal the Sandbox Mode toggle, then enable it
            </Text>
          </View>

          <View style={styles.step}>
            <Text style={styles.stepNumber}>4.</Text>
            <Text style={styles.stepText}>
              Return to this app and tap the button below
            </Text>
          </View>
        </View>

        <View style={styles.warningContainer}>
          <Text style={styles.warningTitle}>Why Sandbox Mode?</Text>
          <Text style={styles.warningText}>
            Sandbox mode allows the wallet to accept credentials from demo
            issuers like this app. Without sandbox mode, the wallet will reject
            credentials from non-production issuers.
          </Text>
        </View>

        <TouchableOpacity style={styles.button} onPress={handleConfirm}>
          <Text style={styles.buttonText}>I've Enabled Sandbox Mode</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    textAlign: 'center',
    marginBottom: 16,
  },
  description: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 24,
  },
  instructionsContainer: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 20,
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  instructionsTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333',
    marginBottom: 16,
  },
  step: {
    flexDirection: 'row',
    marginBottom: 12,
  },
  stepNumber: {
    fontSize: 16,
    fontWeight: '600',
    color: '#1a73e8',
    width: 24,
  },
  stepText: {
    fontSize: 16,
    color: '#333',
    flex: 1,
    lineHeight: 24,
  },
  warningContainer: {
    backgroundColor: '#fff3cd',
    borderRadius: 12,
    padding: 16,
    marginBottom: 24,
    borderLeftWidth: 4,
    borderLeftColor: '#ffc107',
  },
  warningTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#856404',
    marginBottom: 8,
  },
  warningText: {
    fontSize: 14,
    color: '#856404',
    lineHeight: 22,
  },
  button: {
    backgroundColor: '#1a73e8',
    borderRadius: 8,
    paddingVertical: 16,
    paddingHorizontal: 24,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 18,
    fontWeight: '600',
  },
});
