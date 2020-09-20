# Cymptom Candidate Task

## MSRPC using Python

Here is an SAMR Client written as part of the [Cymptom candidate-task](https://github.com/cymptomlabs/candidate-task)
The client can be run from commandline with target argument, or as shell.  
A file can also be provided to run a list of samr_client-shell commands.

It uses [Impacket](https://github.com/SecureAuthCorp/impacket) package and acts as an API for MSRPC protocol (Microsoft implementation of DCE/RPC).
Specifically, it uses MS-SAMR API, as requested in the task, to provide some management functionality:

```
    1. Create a new local user\group
    2. Retrieve all users\groups
```

This repository illustrates how I (at the time of writing) perceive OOP in python, and uses some of the cool python features.

Good luck!

![](https://raw.githubusercontent.com/zivkasper/candidate-task/6f0e37e4ce07dff96d3bb7ed9986973036fc8993/cymptom_logo.svg)
&nbsp;
