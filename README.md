# HASSH - SSH Fingerprinting

[![CI](https://github.com/ArchiMoebius/hassh/workflows/CI/badge.svg)](https://github.com/ArchiMoebius/hassh/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ArchiMoebius/hassh)](https://goreportcard.com/report/github.com/ArchiMoebius/hassh)
[![GoDoc](https://godoc.org/github.com/ArchiMoebius/hassh?status.svg)](https://godoc.org/github.com/ArchiMoebius/hassh)
[![Release](https://img.shields.io/github/release/ArchiMoebius/hassh.svg)](https://github.com/ArchiMoebius/hassh/releases/latest)

# SSH-Proxy

A Golang binary to proxy SSH connections to a backend SSH server - with filtering based upon the HASSH of the remote client.

# SSH-CTL

A Golang binary which provides both a CLI and a TUI for exploring/managing the ssh_connections.db (SQLite3 database which records connection events and client HASSH values) which enforces access based upon HASSH values.