#!/bin/bash

cat message.eml | dkimsign --hcanon relaxed --bcanon relaxed --signalg ed25519-sha256 brisbane football.example.com ed.key > signed.ed.dkimpy.eml
cat signed.ed.dkimpy.eml