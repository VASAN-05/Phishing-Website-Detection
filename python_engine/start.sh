#!/bin/bash
# Start the ATL Python ML Engine
cd "$(dirname "$0")"
pip install -r requirements.txt -q
python api.py
