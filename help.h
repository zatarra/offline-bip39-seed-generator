#ifndef HELP_H
#define HELP_H

#include <Arduino.h>

const char HELP_TEXT[] PROGMEM = 
    "BIP39 Dice Generator\n\n"
    "This app helps you generate a secure BIP39 seed phrase using physical dice rolls.\n\n"
    "Rules:\n"
    "- Dice 1, 2, 3 = Bit 0\n"
    "- Dice 4, 5, 6 = Bit 1\n\n"
    "Entropy Requirements:\n"
    "- 12 Words: 128 total bits = 124 dice bits + 4 SHA256 checksum bits.\n"
    "- 24 Words: 256 total bits = 248 dice bits + 8 SHA256 checksum bits.\n\n"
    "The 11th bit of word 12 (or word 24) combined with the remaining checksum bits forms the final word.";

#endif