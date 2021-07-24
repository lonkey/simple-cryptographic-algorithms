# Simple Cryptographic Algorithms

Python library for demonstrating the functionality of common cryptographic algorithms.

## Requirements

Python 3.7.9 or later.

### Creating a virtual environment

`venv` allows you to manage separate package installations for different projects. It essentially allows you to create
a "virtual" isolated Python installation and install packages into that virtual installation. When you switch projects,
you can simply create a new virtual environment and not have to worry about breaking the packages installed in the other
environments.

```shell
python3 -m venv venv
```

The second argument is the location, and thus the name, to create the virtual environment. Generally, you can just
create this in your project and call it venv. If you name the virtual environment differently, the .gitignore must be
modified accordingly.

### Activating a virtual environment

Before you can start installing or using packages in your virtual environment you’ll need to activate it.

| Command-line    | Script                                       |
|-----------------|----------------------------------------------|
| bash/zsh        | $ source &lt;venv&gt;/bin/activate           |
| fish            | $ source &lt;venv&gt;/bin/activate.fish      |
| csh/tcsh        | $ source &lt;venv&gt;/bin/activate.csh       |
| PowerShell Core | $ &lt;venv&gt;/bin/Activate.ps1              |
| cmd.exe         | C:\\> &lt;venv&gt;\\Scripts\\activate.bat    |
| PowerShell      | PS C:\\> &lt;venv&gt;\\Scripts\\Activate.ps1 |

### Using requirements file

A requirements file contains a list of dependencies to be installed using pip.

```shell
python3 -m pip install -r requirements.txt
```

### Usage

To use, simply uncomment the corresponding function in `main.py` and adjust the sample values if necessary.

```shell
python3 main.py
```

## To Do

- Unify output of mathematical conditions
- Add an English translation
