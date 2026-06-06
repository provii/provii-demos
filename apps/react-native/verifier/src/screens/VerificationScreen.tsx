// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Verification Screen
 *
 * Shows the verification flow:
 * 1. Creates challenge and opens Provii Wallet
 * 2. Displays polling status while waiting for user to verify
 * 3. Shows expiration countdown
 * 4. Navigates to result when complete
 */

import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  Alert,
  Linking,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import type {RootStackParamList} from '../../App';
import {useProviiVerifier} from '../provii/useProviiVerifier';

type Props = NativeStackScreenProps<RootStackParamList, 'Verification'>;

export default function VerificationScreen({navigation, route}: Props) {
  const {threshold} = route.params;
  const {
    state,
    session,
    isLoading,
    error,
    startVerification,
    reset,
  } = useProviiVerifier();

  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);

  // Start verification when screen loads
  useEffect(() => {
    startVerification(threshold.age, threshold.mode);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Update countdown timer
  useEffect(() => {
    if (!session) {return;}

    const updateTimer = () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = session.expiresAt - now;
      setTimeRemaining(remaining > 0 ? remaining : 0);
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [session]);

  // Navigate to result when verification completes
  useEffect(() => {
    if (state === 'redeemed') {
      navigation.replace('Result', {
        verified: true,
        minimumAge: threshold.age,
      });
    } else if (state === 'failed' || state === 'expired') {
      navigation.replace('Result', {
        verified: false,
        minimumAge: threshold.age,
        error: error?.message,
      });
    }
  }, [state, navigation, threshold.age, error]);

  const handleCancel = () => {
    Alert.alert(
      'Cancel Verification',
      'Are you sure you want to cancel this verification?',
      [
        {text: 'Continue Verifying', style: 'cancel'},
        {
          text: 'Cancel',
          style: 'destructive',
          onPress: () => {
            reset();
            navigation.goBack();
          },
        },
      ],
    );
  };

  const handleRetry = () => {
    reset();
    startVerification(threshold.age, threshold.mode);
  };

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getStatusMessage = (): string => {
    switch (state) {
      case 'creating':
        return 'Creating verification challenge...';
      case 'challenge_created':
        return 'Opening Provii Wallet...';
      case 'polling':
        return 'Waiting for verification...';
      case 'verified':
        return 'Age verified! Completing...';
      case 'redeeming':
        return 'Finalizing verification...';
      default:
        return 'Processing...';
    }
  };

  if (error && (state === 'failed' || state === 'expired')) {
    return (
      <View style={styles.container}>
        <View style={styles.errorContainer}>
          <Text style={styles.errorIcon}>❌</Text>
          <Text style={styles.errorTitle}>Verification Failed</Text>
          <Text style={styles.errorMessage}>{error.message}</Text>
          <TouchableOpacity style={styles.retryButton} onPress={handleRetry}>
            <Text style={styles.retryButtonText}>Try Again</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.cancelButton}
            onPress={() => navigation.goBack()}>
            <Text style={styles.cancelButtonText}>Go Back</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.content}>
        <View style={styles.iconContainer}>
          <ActivityIndicator size="large" color="#1a73e8" />
        </View>

        <Text style={styles.title}>{getStatusMessage()}</Text>

        <Text style={styles.subtitle}>
          Please complete the age verification in Provii Wallet and return to
          this app.
        </Text>

        {session && (
          <View style={styles.qrContainer}>
            <QRCode
              value={session.deepLink}
              size={220}
              ecl="M"
              backgroundColor="#FFFFFF"
              color="#000000"
            />
            <Text style={styles.qrLabel}>
              Scan with Provii Wallet on another device
            </Text>
            <TouchableOpacity
              style={styles.openWalletButton}
              onPress={() => {
                if (session.deepLink) {
                  Linking.openURL(session.deepLink);
                }
              }}>
              <Text style={styles.openWalletButtonText}>
                Open Provii Wallet
              </Text>
            </TouchableOpacity>
          </View>
        )}

        {timeRemaining !== null && (
          <View style={styles.timerContainer}>
            <Text style={styles.timerLabel}>Time remaining:</Text>
            <Text style={styles.timerValue}>{formatTime(timeRemaining)}</Text>
          </View>
        )}

        <View style={styles.infoCard}>
          <Text style={styles.infoTitle}>
            Verifying: {threshold.mode === 'under_age' ? `Under ${threshold.age}` : `Age ${threshold.age}+`}
          </Text>
          <Text style={styles.infoText}>
            {threshold.mode === 'under_age'
              ? `The user will prove they are under ${threshold.age} years old using a zero knowledge proof. Their actual date of birth will not be revealed.`
              : `The user will prove they are ${threshold.age} years or older using a zero knowledge proof. Their actual date of birth will not be revealed.`}
          </Text>
        </View>
      </View>

      <View style={styles.footer}>
        <TouchableOpacity
          style={styles.cancelButton}
          onPress={handleCancel}
          disabled={isLoading}>
          <Text style={styles.cancelButtonText}>Cancel Verification</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    flex: 1,
    padding: 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#e3f2fd',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 24,
  },
  title: {
    fontSize: 20,
    fontWeight: '600',
    color: '#333',
    textAlign: 'center',
    marginBottom: 12,
  },
  subtitle: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: 24,
    paddingHorizontal: 20,
  },
  qrContainer: {
    alignItems: 'center',
    marginBottom: 24,
  },
  qrLabel: {
    fontSize: 13,
    color: '#666',
    marginTop: 8,
    textAlign: 'center',
  },
  openWalletButton: {
    backgroundColor: '#1a73e8',
    borderRadius: 12,
    paddingVertical: 14,
    paddingHorizontal: 32,
    marginTop: 16,
    width: '100%',
    alignItems: 'center',
  },
  openWalletButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  timerContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fff',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 20,
    marginBottom: 24,
  },
  timerLabel: {
    fontSize: 14,
    color: '#666',
    marginRight: 8,
  },
  timerValue: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#1a73e8',
  },
  infoCard: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    width: '100%',
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
    marginBottom: 8,
  },
  infoText: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
  footer: {
    padding: 20,
  },
  cancelButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#c62828',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
  },
  cancelButtonText: {
    color: '#c62828',
    fontSize: 16,
    fontWeight: '600',
  },
  errorContainer: {
    flex: 1,
    padding: 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  errorIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  errorTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#c62828',
    marginBottom: 8,
  },
  errorMessage: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    marginBottom: 24,
  },
  retryButton: {
    backgroundColor: '#1a73e8',
    borderRadius: 12,
    paddingVertical: 16,
    paddingHorizontal: 32,
    marginBottom: 12,
  },
  retryButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
});
