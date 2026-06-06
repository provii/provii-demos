// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Verifier Demo App
 *
 * Demonstrates how third-party apps integrate with Provii for age verification.
 * This app shows the complete verifier flow:
 * 1. Select age threshold
 * 2. Create challenge and open Provii Wallet
 * 3. Poll for verification status
 * 4. Display result
 */

import React from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {createNativeStackNavigator} from '@react-navigation/native-stack';

import SandboxInstructionsScreen from './src/screens/SandboxInstructionsScreen';
import AgeThresholdScreen from './src/screens/AgeThresholdScreen';
import VerificationScreen from './src/screens/VerificationScreen';
import ResultScreen from './src/screens/ResultScreen';
import type {AgeThreshold} from './src/types';

export type RootStackParamList = {
  SandboxInstructions: undefined;
  AgeThreshold: undefined;
  Verification: {threshold: AgeThreshold};
  Result: {verified: boolean; minimumAge: number; error?: string};
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName="SandboxInstructions"
        screenOptions={{
          headerStyle: {
            backgroundColor: '#1a73e8',
          },
          headerTintColor: '#fff',
          headerTitleStyle: {
            fontWeight: '600',
          },
        }}>
        <Stack.Screen
          name="SandboxInstructions"
          component={SandboxInstructionsScreen}
          options={{title: 'Getting Started'}}
        />
        <Stack.Screen
          name="AgeThreshold"
          component={AgeThresholdScreen}
          options={{title: 'Verify Age'}}
        />
        <Stack.Screen
          name="Verification"
          component={VerificationScreen}
          options={{
            title: 'Verifying...',
            headerBackVisible: false,
          }}
        />
        <Stack.Screen
          name="Result"
          component={ResultScreen}
          options={{
            title: 'Result',
            headerBackVisible: false,
          }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
