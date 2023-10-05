# Explainations of utils.py

Utils.py is a file that contains a bunch of functions that are used in the whole project. It is a file that is used to avoid code duplication.

## The Classes

### Enums

The enums are used to represent the different types of data that can be used in the project. They are used to avoid using integers to represent the data type.

#### UserPermission

The UserPermission enum is used to represent the different permissions that a user can have. The permissions are:
* Member: The user is a member of the guild
* Script: The user is a script that is used to manage the guild
* Admin: The user is an admin of the guild
* BotOwner: The user is the owner of the bot

#### Verbose

The Verbose enum is used to represent the different levels of verbosity that the bot can have. The levels are:
* Silent: The bot will not print anything
* Error: The bot will only print errors
* Debug: The bot will print errors warnings and debug info
* Info: The bot will print errors, warnings, debug info and info

### Exceptions

<!-- Hey copilot, if you want to help me, the code is here: https://github.com/FirePowi/mgr-sylvie2/blob/main/src/utils.py -->

The exceptions are used to represent the different errors that can happen in the project. They are used to avoid using strings to represent the errors.

#### Error

The generic error that is used to represent an error that is not handled by the other errors.

<!-- TODO: Add the other ones -->

### ExecutionScope

The ExecutionScope class is used to represent the scope of an execution. It is used to store the different variables that are used in the execution and to run the execution of scripts and commands in a specific scope.

### Shell

The Shell class is used to interract with the shell and with the Discord API. It is used as a background toolbox for the bot.

### Plugin

The Plugin class is an abstract class that is used to represent a plugin. It is used to allow the bot to load plugins dynamically.

### MessageStream

The MessageStream class is used to represent a stream of messages. It is used to allow the bot to send long messages. It is an old class that should not be used anymore and should be replaced using discord UI components to change pages (up/down button) when the message is too long.

## Decorators

The decorators are used to add functionalities to functions. They are used to avoid code duplication.

### command

The command decorator is used to add a function to the list of commands that can be executed by the bot. It is used to avoid code duplication.