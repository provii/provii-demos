// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import React, {useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
} from 'react-native';
import {useProviiIssuer} from '../provii/useProviiIssuer';
import {demoAges, calculateDobForAge, DemoAge} from '../types';

export default function AgeSelectionScreen(): React.JSX.Element {
  const {issueCredential, isLoading, error, clearError} = useProviiIssuer();
  const [selectedAge, setSelectedAge] = useState<DemoAge | null>(null);
  const [issuedSuccessfully, setIssuedSuccessfully] = useState(false);

  const handleAgePress = async (age: DemoAge) => {
    setSelectedAge(age);
    setIssuedSuccessfully(false);
    clearError();

    const dob = calculateDobForAge(age);
    const success = await issueCredential(dob);

    if (success) {
      setIssuedSuccessfully(true);
    }
  };

  const handleReset = () => {
    setSelectedAge(null);
    setIssuedSuccessfully(false);
    clearError();
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.bankEmoji}>{'<bank>'}</Text>
          <Text style={styles.bankTitle}>Demo Bank</Text>
        </View>

        {/* Title Section */}
        <Text style={styles.title}>Issue Age Credential</Text>
        <Text style={styles.subtitle}>
          Tap an age to issue a demo credential to Provii Wallet
        </Text>

        {/* Age Buttons Grid */}
        <View style={styles.ageGrid}>
          {demoAges.map(age => (
            <TouchableOpacity
              key={age}
              style={[
                styles.ageButton,
                selectedAge === age && styles.ageButtonSelected,
                isLoading && styles.ageButtonDisabled,
              ]}
              onPress={() => handleAgePress(age)}
              disabled={isLoading}>
              {isLoading && selectedAge === age ? (
                <ActivityIndicator color="#fff" size="small" />
              ) : (
                <Text
                  style={[
                    styles.ageButtonText,
                    selectedAge === age && styles.ageButtonTextSelected,
                  ]}>
                  {age}
                </Text>
              )}
            </TouchableOpacity>
          ))}
        </View>

        {/* Loading Indicator */}
        {isLoading && (
          <View style={styles.statusCard}>
            <ActivityIndicator color="#2e7d32" size="large" />
            <Text style={styles.statusText}>
              Creating credential for age {selectedAge}...
            </Text>
          </View>
        )}

        {/* Success Card */}
        {issuedSuccessfully && !isLoading && (
          <View style={styles.successCard}>
            <Text style={styles.successTitle}>Credential Issued!</Text>
            <Text style={styles.successText}>
              A credential for age {selectedAge} has been sent to Provii Wallet.
            </Text>
            <TouchableOpacity
              style={styles.issueAnotherButton}
              onPress={handleReset}>
              <Text style={styles.issueAnotherButtonText}>Issue Another</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* Error Card */}
        {error && !isLoading && (
          <View style={styles.errorCard}>
            <Text style={styles.errorTitle}>Error</Text>
            <Text style={styles.errorText}>{error.message}</Text>
            <TouchableOpacity
              style={styles.retryButton}
              onPress={handleReset}>
              <Text style={styles.retryButtonText}>Try Again</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* Footer */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>
            Demo App - Not for production use
          </Text>
        </View>
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
  header: {
    alignItems: 'center',
    marginBottom: 24,
    paddingTop: 16,
  },
  bankEmoji: {
    fontSize: 48,
    marginBottom: 8,
    color: '#2e7d32',
  },
  bankTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#2e7d32',
  },
  title: {
    fontSize: 24,
    fontWeight: '600',
    color: '#333',
    textAlign: 'center',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    marginBottom: 32,
    lineHeight: 22,
  },
  ageGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'center',
    gap: 12,
    marginBottom: 24,
  },
  ageButton: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#e8f5e9',
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#2e7d32',
  },
  ageButtonSelected: {
    backgroundColor: '#2e7d32',
  },
  ageButtonDisabled: {
    opacity: 0.6,
  },
  ageButtonText: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2e7d32',
  },
  ageButtonTextSelected: {
    color: '#fff',
  },
  statusCard: {
    backgroundColor: '#e8f5e9',
    borderRadius: 12,
    padding: 24,
    marginBottom: 16,
    alignItems: 'center',
  },
  statusText: {
    fontSize: 16,
    color: '#2e7d32',
    marginTop: 12,
    textAlign: 'center',
  },
  successCard: {
    backgroundColor: '#e8f5e9',
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
    borderLeftWidth: 4,
    borderLeftColor: '#2e7d32',
  },
  successTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#2e7d32',
    marginBottom: 8,
  },
  successText: {
    fontSize: 14,
    color: '#2e7d32',
    lineHeight: 22,
    marginBottom: 16,
  },
  issueAnotherButton: {
    backgroundColor: '#2e7d32',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 24,
    alignItems: 'center',
  },
  issueAnotherButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  errorCard: {
    backgroundColor: '#ffebee',
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
    borderLeftWidth: 4,
    borderLeftColor: '#c62828',
  },
  errorTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#c62828',
    marginBottom: 8,
  },
  errorText: {
    fontSize: 14,
    color: '#c62828',
    lineHeight: 22,
    marginBottom: 16,
  },
  retryButton: {
    backgroundColor: '#c62828',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 24,
    alignItems: 'center',
  },
  retryButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  footer: {
    marginTop: 32,
    paddingTop: 16,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
    alignItems: 'center',
  },
  footerText: {
    fontSize: 12,
    color: '#999',
    textAlign: 'center',
  },
});
