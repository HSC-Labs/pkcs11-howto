# PKCS11 Random generator demo

## Description

A small demonstrator of the use of a PKCS#11 token (tested with a Feitan
epass2003) for hardware supported random number generation.

## Dependencies

 * GCC version 4 and followin supporting std=c99 language level
 * POSIX environment
 * libDL

## Building

    gcc random-p11.c ckr_message.c --std=c99 -I include -ldl -Wall -Wextra -pedantic -o testp11 

## Running

    ./testp11

## Token initialisation
    pkcs15-init -E
    pkcs15-init --create-pkcs15 --profile pkcs15+onepin --use-default-transport-key --auth-id 01 --puk-id 01 --pin 0000 --puk 111111 --label "PKCS11 test"

## Legal


Tous droits réservés Hervé Schauer Consultants(HSC) 2016

Ce logiciel est licencié selon les termes de la licence Apache 2.0.

Vous pouvez obtenir une copie de cette Licence at l'adresse:

    <http://www.apache.org/licenses/LICENSE-2.0>

Sauf exceptions prévues par la loi, ce logiciel est livré en l'état 
et aucune garantie explicite ou implicite quand à son usage n'est 
fournie par HSC.

Ce code est dérivé de PKCS#11 Cryptographic Token Interface 
(Cryptoki) fournit par RSA Security Inc. 

---

Copyright 2016 Hervé Schauer Consultants(HSC)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


This code is derived from the RSA Security Inc. PKCS #11 Cryptographic
Token Interface (Cryptoki).

