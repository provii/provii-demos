// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import React from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {createNativeStackNavigator} from '@react-navigation/native-stack';

import SandboxInstructionsScreen from './src/screens/SandboxInstructionsScreen';
import AgeSelectionScreen from './src/screens/AgeSelectionScreen';

export type RootStackParamList = {
  SandboxInstructions: undefined;
  AgeSelection: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

function App(): React.JSX.Element {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName="SandboxInstructions"
        screenOptions={{
          headerStyle: {
            backgroundColor: '#2e7d32',
          },
          headerTintColor: '#fff',
          headerTitleStyle: {
            fontWeight: 'bold',
          },
        }}>
        <Stack.Screen
          name="SandboxInstructions"
          component={SandboxInstructionsScreen}
          options={{title: 'Sandbox Setup'}}
        />
        <Stack.Screen
          name="AgeSelection"
          component={AgeSelectionScreen}
          options={{title: 'Demo Bank'}}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default App;
