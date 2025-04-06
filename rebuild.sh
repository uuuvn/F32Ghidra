#!/bin/sh
set -xeo pipefail
rm -rf dist/*
export GHIDRA_INSTALL_DIR=$HOME/src/ghidra_11.3.1_PUBLIC
gradle buildExtension
FILE="$PWD/dist/*"
cd ~/Library/ghidra/ghidra_11.3.1_PUBLIC/Extensions
rm -rf F32Ghidra
unzip $FILE
~/src/ghidra_11.3.1_PUBLIC/ghidraRun
