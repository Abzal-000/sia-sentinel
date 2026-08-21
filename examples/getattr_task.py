import os

def run_command(cmd):
    return getattr(os, 'system')(cmd)
