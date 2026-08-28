"""Bait for the Python rules. One construct per rule."""
# built at C:\Users\jsmith\projects\rt2411          <- build-path-leak
import os, pickle, socket

C2 = "10.20.30.40:4444"                             # hardcoded-c2-address


def load(b):
    return pickle.loads(b)                          # insecure-deserialization


def run(cmd):
    os.system(cmd)                                  # command-injection-via-shell


def serve():
    s = socket.socket()
    s.bind(("0.0.0.0", 4444))                       # control-channel-on-all-interfaces
    s.listen(5)


# TODO(jsmith): strip before shipping              <- operator-todo
