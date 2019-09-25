![logo](cymptom_logo.svg | width=250)

# Cymptom Candidate Task

## MSRPC using Python
In the following task you’re going to use MSRPC protocol (Microsoft implementation of DCERPC) in order to write a system for managing accounts of a remote Windows machines (both local and domain
accounts).

In specific, you will use MS-SAMR interface API which provides managements functionality for an
account store or directory. You will find any information regarding the interface in the following link.
You are not required to implement the whole MS-SAMR interface. Most of the work was already done
for you by Impacket project. The project contains an implementation for most MSRPC interfaces with
examples and test cases.
Your system should support the following functionality:
1. Create a new local user\group
2. Retrieve all users\groups
3. Delete a user\group

The command will be received by the user and the system will operate accordingly.
For start, try to implement a piece of code for the following example. This example emphasizes the
sequence of methods required in order to create a user account on a remote system. You will need to
understand each function, how does it work, and the relevant structures involved.
Next, extend it to fully support all the functionality required.

### Requirements
- You should be using Python 3.6+
- You are required to write your code using OOP concepts
- Document your code as much as needed

### Before starting this task
- Fork this repository ([https://github.com/cymptomlabs/candidate-task.git](https://github.com/cymptomlabs/candidate-task.git)).
- Send a link to the forked github repository to: itamar@cymptom.com .

**Good luck!**