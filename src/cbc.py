#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Feb 23 2023

@author: iluzioDev

This script implements AES algorithm.
"""
import aes
from colorama import Fore

ROW = '■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■'

def main():
  """Main function of the script.
  """
  while(True):
    print(ROW)
    print('■                            WELCOME TO THE CBC MODE TOOL!                            ■')
    print(ROW)
    print('What do you want to do?')
    print('[1] AES Cipher with CBC Mode.')
    print('[0] Exit.')
    print(ROW)
    option = input('Option  ->  ')
    print(ROW)
  
    if int(option) not in range(2):
      print('Invalid option!')
      
    if option == '0':
      print('See you soon!')
      print(ROW)
      break
    
    if option == '1':
      key = input('Insert Key (up to 16 bytes)  ->  ').replace(' ', '')
      print(ROW)
      if len(key) > 32:
        print('Key must be up to 16 bytes!')
        continue
      key = key.zfill(32)
      
      i_vector = input('Enter the initialization vector  -> ').replace(' ', '')
      print(ROW)
      if len(i_vector) > 32:
        print('Invalid initialization vector! - Too large')
        continue
      i_vector = i_vector.zfill(32)
      
      plaintext = input('Enter plain text  -> ').replace(' ', '')
      print(ROW)
      text_blocks = []

      while len(plaintext) >= 32:
        text_blocks.append(plaintext[:32])
        plaintext = plaintext[32:]
        
      if len(plaintext) != 0:
        text_blocks.append(plaintext)
      
      xor_blocks = []
      encrypted_blocks = []
      length = 0
      for i in range(len(text_blocks)):
        if i != 0 and i == len(text_blocks) - 1 and len(text_blocks[i]) != 32:
          length = len(text_blocks[i])
          text_blocks[i] = text_blocks[i][::-1].zfill(32)[::-1]
          xor_blocks.append(hex(int(text_blocks[i], 16) ^ int(encrypted_blocks[i - 1], 16))[2:].zfill(32))
          last = encrypted_blocks[i - 1]
        elif i != 0:
          text_blocks[i] = text_blocks[i].zfill(32)
          xor_blocks.append(hex(int(text_blocks[i], 16) ^ int(encrypted_blocks[i - 1], 16))[2:].zfill(32))
        else:
          xor_blocks.append(hex(int(text_blocks[i], 16) ^ int(i_vector, 16))[2:].zfill(32))
  
        encrypted_blocks.append(aes.encrypt(xor_blocks[i], key))
        if i != 0:
          encrypted_blocks[i - 1] = encrypted_blocks[i]
          encrypted_blocks[i] = last[:length]
        print(ROW)
        
      print('■                             ENCRYPTED TEXT                                          ■')
      print(ROW)
      for i in range(len(encrypted_blocks)):
        print(Fore.YELLOW + 'Block ' + str(i + 1) + '  ->  ' + Fore.CYAN + encrypted_blocks[i] + Fore.RESET)
      
    
  return

if __name__ == '__main__':
  main()