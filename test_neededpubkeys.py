#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

try:
    import state
    print("state.neededPubkeys type:", type(state.neededPubkeys))
    print("Number of keys:", len(state.neededPubkeys))
    
    if state.neededPubkeys:
        print("\nFirst few keys:")
        for i, key in enumerate(list(state.neededPubkeys.keys())[:5]):
            print(f"  {i}. Type: {type(key)}, Value: {repr(key)[:50]}")
            value = state.neededPubkeys[key]
            print(f"     -> Address: {value[0]}, Cryptor: {type(value[1])}")
    else:
        print("state.neededPubkeys is empty")
except Exception as e:
    print(f"Error: {e}")
