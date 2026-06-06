// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Sandbox Instructions Screen
 *
 * Guides the user to enable sandbox mode in Provii Wallet before
 * proceeding with verification testing.
 */

import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import type {RootStackParamList} from '../../App';

const SANDBOX_CONFIRMED_KEY = 'verifier_sandbox_confirmed';

type Props = NativeStackScreenProps<RootStackParamList, 'SandboxInstructions'>;

export default function SandboxInstructionsScreen({navigation}: Props) {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user has already confirmed sandbox mode
    AsyncStorage.getItem(SANDBOX_CONFIRMED_KEY)
      .then(value => {
        if (value === 'true') {
          navigation.replace('AgeThreshold');
        } else {
          setIsLoading(false);
        }
      })
      .catch(() => {
        // Storage read failed; show the instructions screen as fallback
        setIsLoading(false);
      });
  }, [navigation]);

  const handleConfirm = async () => {
    try {
      await AsyncStorage.setItem(SANDBOX_CONFIRMED_KEY, 'true');
    } catch {
      // Storage write failed; proceed anyway since the confirmation is non-critical
    }
    navigation.replace('AgeThreshold');
  };

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#1a73e8" />
      </View>
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.warningIcon}>⚠️</Text>
        <Text style={styles.title}>Enable Sandbox Mode</Text>
      </View>

      <Text style={styles.subtitle}>
        Before testing age verification, you need to enable Sandbox Mode in Provii
        Wallet. This allows testing without real credentials.
      </Text>

      <View style={styles.stepsContainer}>
        <Text style={styles.stepsTitle}>Instructions:</Text>

        <View style={styles.step}>
          <Text style={styles.stepNumber}>1</Text>
          <Text style={styles.stepText}>Open Provii Wallet on your device</Text>
        </View>

        <View style={styles.step}>
          <Text style={styles.stepNumber}>2</Text>
          <Text style={styles.stepText}>Go to Settings (gear icon)</Text>
        </View>

        <View style={styles.step}>
          <Text style={styles.stepNumber}>3</Text>
          <Text style={styles.stepText}>
            Tap the screen 5 times to reveal developer options
          </Text>
        </View>

        <View style={styles.step}>
          <Text style={styles.stepNumber}>4</Text>
          <Text style={styles.stepText}>Enable "Sandbox Mode"</Text>
        </View>

        <View style={styles.step}>
          <Text style={styles.stepNumber}>5</Text>
          <Text style={styles.stepText}>
            The app will restart in sandbox mode
          </Text>
        </View>
      </View>

      <View style={styles.infoBox}>
        <Text style={styles.infoText}>
          In sandbox mode, you can use demo credentials that were issued from
          the Provii Issuer Demo app for testing age verification.
        </Text>
      </View>

      <TouchableOpacity style={styles.button} onPress={handleConfirm}>
        <Text style={styles.buttonText}>I've Enabled Sandbox Mode</Text>
      </TouchableOpacity>
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
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f5f5f5',
  },
  header: {
    alignItems: 'center',
    marginBottom: 20,
  },
  warningIcon: {
    fontSize: 48,
    marginBottom: 12,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 24,
  },
  stepsContainer: {
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
  stepsTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333',
    marginBottom: 16,
  },
  step: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: 16,
  },
  stepNumber: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: '#1a73e8',
    color: '#fff',
    fontSize: 14,
    fontWeight: 'bold',
    textAlign: 'center',
    lineHeight: 28,
    marginRight: 12,
  },
  stepText: {
    flex: 1,
    fontSize: 16,
    color: '#333',
    lineHeight: 24,
  },
  infoBox: {
    backgroundColor: '#e3f2fd',
    borderRadius: 12,
    padding: 16,
    marginBottom: 24,
  },
  infoText: {
    fontSize: 14,
    color: '#1565c0',
    lineHeight: 20,
  },
  button: {
    backgroundColor: '#1a73e8',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
});
