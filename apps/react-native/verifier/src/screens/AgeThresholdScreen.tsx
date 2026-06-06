// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Age Threshold Selection Screen
 *
 * Allows the user to select which age threshold to verify.
 * Supports both over-age and under-age verification modes.
 */

import React, {useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  FlatList,
} from 'react-native';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import type {RootStackParamList} from '../../App';
import type {AgeThreshold, VerificationMode} from '../types';

type Props = NativeStackScreenProps<RootStackParamList, 'AgeThreshold'>;

const overAgeThresholds: AgeThreshold[] = [
  {
    id: 'over-13',
    age: 13,
    title: 'Age 13+ Verification',
    description: 'Verify the user is 13 years or older (COPPA compliance)',
    mode: 'over_age',
  },
  {
    id: 'over-18',
    age: 18,
    title: 'Age 18+ Verification',
    description: 'Verify the user is 18 years or older (general adult content)',
    mode: 'over_age',
  },
  {
    id: 'over-21',
    age: 21,
    title: 'Age 21+ Verification',
    description: 'Verify the user is 21 years or older (alcohol, cannabis)',
    mode: 'over_age',
  },
  {
    id: 'over-25',
    age: 25,
    title: 'Age 25+ Verification',
    description: 'Verify the user is 25 years or older (car rental, etc.)',
    mode: 'over_age',
  },
];

const underAgeThresholds: AgeThreshold[] = [
  {
    id: 'under-13',
    age: 13,
    title: 'Under 13 Verification',
    description: "Verify the user is under 13 years old (children's content)",
    mode: 'under_age',
  },
  {
    id: 'under-16',
    age: 16,
    title: 'Under 16 Verification',
    description:
      'Verify the user is under 16 years old (GDPR parental consent)',
    mode: 'under_age',
  },
  {
    id: 'under-18',
    age: 18,
    title: 'Under 18 Verification',
    description: 'Verify the user is under 18 years old (minor status)',
    mode: 'under_age',
  },
  {
    id: 'under-21',
    age: 21,
    title: 'Under 21 Verification',
    description: 'Verify the user is under 21 years old (youth programs)',
    mode: 'under_age',
  },
];

export default function AgeThresholdScreen({navigation}: Props) {
  const [selectedMode, setSelectedMode] =
    useState<VerificationMode>('over_age');

  const thresholds =
    selectedMode === 'over_age' ? overAgeThresholds : underAgeThresholds;

  const handleSelect = (threshold: AgeThreshold) => {
    navigation.navigate('Verification', {threshold});
  };

  const renderThreshold = ({item}: {item: AgeThreshold}) => (
    <TouchableOpacity
      style={styles.card}
      onPress={() => handleSelect(item)}
      activeOpacity={0.7}>
      <View style={styles.cardContent}>
        <View
          style={[
            styles.ageCircle,
            item.mode === 'under_age' && styles.ageCircleUnder,
          ]}>
          <Text
            style={[
              styles.ageText,
              item.mode === 'under_age' && styles.ageTextUnder,
            ]}>
            {item.mode === 'over_age' ? `${item.age}+` : `<${item.age}`}
          </Text>
        </View>
        <View style={styles.cardTextContainer}>
          <Text style={styles.cardTitle}>{item.title}</Text>
          <Text style={styles.cardDescription}>{item.description}</Text>
        </View>
        <Text style={styles.chevron}>›</Text>
      </View>
    </TouchableOpacity>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Select Age Threshold</Text>

        {/* Mode toggle */}
        <View style={styles.modeToggle}>
          <TouchableOpacity
            style={[
              styles.modeButton,
              selectedMode === 'over_age' && styles.modeButtonActive,
            ]}
            onPress={() => setSelectedMode('over_age')}
            activeOpacity={0.7}>
            <Text
              style={[
                styles.modeButtonText,
                selectedMode === 'over_age' && styles.modeButtonTextActive,
              ]}>
              Over Age
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[
              styles.modeButton,
              selectedMode === 'under_age' && styles.modeButtonActive,
            ]}
            onPress={() => setSelectedMode('under_age')}
            activeOpacity={0.7}>
            <Text
              style={[
                styles.modeButtonText,
                selectedMode === 'under_age' && styles.modeButtonTextActive,
              ]}>
              Under Age
            </Text>
          </TouchableOpacity>
        </View>

        <Text style={styles.subtitle}>
          {selectedMode === 'over_age'
            ? 'Choose the minimum age you want to verify. The user will prove they meet this requirement without revealing their actual date of birth.'
            : 'Choose the maximum age you want to verify. The user will prove they are under this age without revealing their actual date of birth.'}
        </Text>
      </View>

      <FlatList
        data={thresholds}
        renderItem={renderThreshold}
        keyExtractor={item => item.id}
        contentContainerStyle={styles.list}
        showsVerticalScrollIndicator={false}
      />

      <View style={styles.footer}>
        <Text style={styles.footerText}>
          Powered by zero knowledge proofs. The user's actual age is never
          revealed to your application.
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    padding: 20,
    paddingBottom: 12,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 12,
  },
  modeToggle: {
    flexDirection: 'row',
    backgroundColor: '#e0e0e0',
    borderRadius: 8,
    padding: 2,
    marginBottom: 12,
  },
  modeButton: {
    flex: 1,
    paddingVertical: 10,
    alignItems: 'center',
    borderRadius: 6,
  },
  modeButtonActive: {
    backgroundColor: '#fff',
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 1},
    shadowOpacity: 0.1,
    shadowRadius: 2,
    elevation: 2,
  },
  modeButtonText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#666',
  },
  modeButtonTextActive: {
    color: '#1a73e8',
  },
  subtitle: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
  list: {
    padding: 20,
    paddingTop: 8,
  },
  card: {
    backgroundColor: '#fff',
    borderRadius: 12,
    marginBottom: 12,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  cardContent: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
  },
  ageCircle: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: '#e3f2fd',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 16,
  },
  ageCircleUnder: {
    backgroundColor: '#fff3e0',
  },
  ageText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#1a73e8',
  },
  ageTextUnder: {
    color: '#e65100',
  },
  cardTextContainer: {
    flex: 1,
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
    marginBottom: 4,
  },
  cardDescription: {
    fontSize: 13,
    color: '#666',
    lineHeight: 18,
  },
  chevron: {
    fontSize: 24,
    color: '#999',
    marginLeft: 8,
  },
  footer: {
    padding: 20,
    paddingTop: 8,
  },
  footerText: {
    fontSize: 12,
    color: '#999',
    textAlign: 'center',
    lineHeight: 18,
  },
});
