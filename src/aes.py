#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Feb 23 2023

@author: iluzioDev

This script implements AES algorithm.
"""
from colorama import Fore

ROW = '■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■'

def splitNbyN(x, n):
  if n < 1:
    raise ValueError('n must be a positive integer!')
  if n > len(x):
    raise ValueError('n must be less than the string length!')
  if len(x) % n != 0:
    raise ValueError('String length is not a multiple of n!')
  return [x[i:i + n] for i in range(0, len(x), n)]

def generateRijndaelSBox():
  T = [0] * 256
  S = [0] * 256

  x = 1
  for i in range(256):
    T[i] = x
    x ^= (x << 1) ^ ((x >> 7) * 0x11B)

  S[0] = hex(0x63)[2:].zfill(2)
  for i in range(255):
    x = T[255 - i]
    x |= x << 8
    x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7)
    S[T[i]] = hex((x ^ 0x63) & 0xFF)[2:].zfill(2)

  return splitNbyN(S, 16)

def generateRoundConstants():
  RC = [['01', '00', '00', '00'],
        ['02', '00', '00', '00'],
        ['04', '00', '00', '00'],
        ['08', '00', '00', '00'],
        ['10', '00', '00', '00'],
        ['20', '00', '00', '00'],
        ['40', '00', '00', '00'],
        ['80', '00', '00', '00'],
        ['1B', '00', '00', '00'],
        ['36', '00', '00', '00']]
  return RC

def subBytes(state, SBOX):
  for i in range(len(state)):
    if type(state[i]) == list:
      for j in range(len(state[i])):
        state[i][j] = SBOX[int(state[i][j][0], 16)][int(state[i][j][1], 16)]
    else:
      state[i] = SBOX[int(state[i][0], 16)][int(state[i][1], 16)]
  return state

def shiftRows(state):
  newstate = []
  for i in range(len(state)):
    newstate.append([])
    for j in range(len(state[i])):
      newstate[i].append(state[i][(j + i) % 4])
  return newstate

def gmul(a, b):
  if b == 1:
    return a
  tmp = (a << 1) & 0xff
  if b == 2:
    return tmp if a < 128 else tmp ^ 0x1b
  if b == 3:
    return gmul(a, 2) ^ a

def mixColumns(state):
  new_state = [[0 for _ in range(4)] for _ in range(4)]
  for i in range(4):
    new_state[0][i] = gmul(int(state[0][i], 16), 2) ^ gmul(int(state[1][i], 16), 3) ^ gmul(int(state[2][i], 16), 1) ^ gmul(int(state[3][i], 16), 1)
    new_state[1][i] = gmul(int(state[0][i], 16), 1) ^ gmul(int(state[1][i], 16), 2) ^ gmul(int(state[2][i], 16), 3) ^ gmul(int(state[3][i], 16), 1)
    new_state[2][i] = gmul(int(state[0][i], 16), 1) ^ gmul(int(state[1][i], 16), 1) ^ gmul(int(state[2][i], 16), 2) ^ gmul(int(state[3][i], 16), 3)
    new_state[3][i] = gmul(int(state[0][i], 16), 3) ^ gmul(int(state[1][i], 16), 1) ^ gmul(int(state[2][i], 16), 1) ^ gmul(int(state[3][i], 16), 2)
  
  for i in range(4):
    for j in range(4):
      new_state[i][j] = hex(new_state[i][j])[2:].zfill(2)
  
  return new_state

def addRoundKey(state, key):
  for i in range(len(state)):
    for j in range(len(state[i])):
      state[i][j] = hex(int(state[i][j], 16) ^ int(key[i][j], 16))[2:].zfill(2)
  return state

def keyExpansion(key, SBOX, RC):
  w = []
  for i in range(11):
    w.append([])
    for j in range(4):
      w[i].append([])
      for k in range(4):
        w[i][j].append(None)
    
  for i in range(4):
    for j in range(4):
      w[0][i][j] = key[i][j]
  
  for i in range(10):
    # RotWord
    wordi_1 = [w[i][1][3], w[i][2][3], w[i][3][3], w[i][0][3]]
    # SubWord
    wordi_1 = subBytes(wordi_1, SBOX)
    
    wordi_4 = [w[i][0][0], w[i][1][0], w[i][2][0], w[i][3][0]]
    # XOR
    for j in range(4):
      w[i + 1][j][0] = hex(int(wordi_4[j], 16) ^ int(wordi_1[j], 16) ^ int(RC[i][j], 16))[2:].zfill(2)
      
    for j in range(4):
      for k in range(1, 4):
        w[i + 1][j][k] = hex(int(w[i + 1][j][k - 1], 16) ^ int(w[i][j][k - 4], 16))[2:].zfill(2)
  return w

def formatState(state):
  return ''.join([''.join([state[i][j] for i in range(4)]) for j in range(4)])

def printIteration(it, state, key):
  print(Fore.YELLOW + str(it), '\t', Fore.GREEN + formatState(state), '\t', Fore.CYAN + formatState(key) + Fore.RESET)

def encrypt(plaintext, key):
  header = Fore.YELLOW + 'IT' + Fore.GREEN + '\t\t      STATE' + Fore.BLUE + '\t\t\t\t      SUBKEY' + Fore.RESET
  state = []
  cipherkey = []
  for i in range(4):
    state.append([])
    cipherkey.append([])
    
  for i in range(4):
    for j in range(4):
      state[i].append(None)
      cipherkey[i].append(None)
  
  for i in range(4):
    for j in range(4):
      state[j][i] = plaintext[i * 8 + j * 2] + plaintext[i * 8 + j * 2 + 1]
      cipherkey[j][i] = key[i * 8 + j * 2] + key[i * 8 + j * 2 + 1]
  
  SBOX = generateRijndaelSBox()
  RC = generateRoundConstants()
  keySchedule = keyExpansion(cipherkey, SBOX, RC)
  
  it = 0
  print(header)
  print(ROW)
  state = addRoundKey(state, cipherkey)
  printIteration(it, state, keySchedule[it])
  it += 1
  for i in range(9):
    state = subBytes(state, SBOX)
    state = shiftRows(state)
    state = mixColumns(state)
    state = addRoundKey(state, keySchedule[i + 1])
    printIteration(it, state, keySchedule[it])
    it += 1
  state = subBytes(state, SBOX)
  state = shiftRows(state)
  state = addRoundKey(state, keySchedule[10])
  printIteration(it, state, keySchedule[it])
  
  encrypted = ''
  for i in range(4):
    for j in range(4):
      encrypted += state[j][i]
  
  return encrypted

def main():
  """Main function of the script.
  """
  while(True):
    print(ROW)
    print('■                           WELCOME TO THE AES CIPHER TOOL!                           ■')
    print(ROW)
    print('What do you want to do?')
    print('[1] AES Cipher.')
    print('[0] Exit.')
    print(ROW)
    option = input('Option  ->  ')
    print(ROW)
  
    if int(option) not in range(5):
      print('Invalid option!')
      continue

    if option == '0':
      print('See you soon!')
      print(ROW)
      break
    
    if option == '1':
      plaintext = input('Insert Plaintext (up to 16 bytes)  ->  ').replace(' ', '')
      print(ROW)
      if len(plaintext) > 32:
        print('Plaintext must be up to 16 bytes!')
        continue
      plaintext = plaintext.zfill(32)
      key = input('Insert Key (up to 16 bytes)  ->  ').replace(' ', '')
      print(ROW)
      if len(key) > 32:
        print('Key must be up to 16 bytes!')
        continue
      key = key.zfill(32)
      
      encrypted = encrypt(plaintext, key)
      print(ROW)
      print('Encrypted Text: ' + Fore.GREEN + encrypted + Fore.RESET)
    
  return

if __name__ == '__main__':
  main()