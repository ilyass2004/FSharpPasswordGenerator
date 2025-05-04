# F# Secure Password Generator

A robust, cryptographically secure password generator built in F#. This application allows you to generate strong passwords with various complexity requirements and analyze existing passwords for security strength.


## Features

- **Multiple Strength Levels**: Generate passwords with predefined security levels (Basic, Medium, Strong, VeryStrong, or Custom)
- **Cryptographically Secure**: Uses .NET's RandomNumberGenerator for true randomness
- **Customizable Rules**:
  - Password length
  - Character types (uppercase, lowercase, numbers, special characters)
  - Minimum requirements for each character type
  - Exclude similar or ambiguous characters
  - Avoid repeated/sequential characters and dictionary words
- **Password Analysis**:
  - Entropy calculation
  - Crack time estimation
  - Strength scoring
  - Improvement suggestions
- **CLI Interface**:
  - Generate single or multiple passwords
  - Save passwords to file
  - Analyze existing passwords

## Requirements

- .NET 6.0 or later
- F# 6.0 or later

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/fsharp-password-generator.git
cd fsharp-password-generator
```

Build the project:

```bash
dotnet build
```

## Usage

### Basic Usage

Generate a password with medium strength:

```bash
dotnet run
```

### Command Line Options

```
Options:
  --strength <value>    Set password strength (basic, medium, strong, verystrong, custom)
  --count <value>       Number of passwords to generate
  --length <value>      Custom password length
  --output <filename>   Save generated passwords to file
  --analyze             Analyze password strength
  --password <value>    Password to analyze
  --help                Display this help message
```

### Examples

Generate 5 strong passwords:

```bash
dotnet run -- --strength strong --count 5
```

Generate a custom length password:

```bash
dotnet run -- --strength medium --length 16
```

Save passwords to a file:

```bash
dotnet run -- --count 10 --output passwords.txt
```

Analyze an existing password:

```bash
dotnet run -- --analyze --password "YourPasswordHere"
```

## Code Structure

- **Config**: Types and functions for password configuration
- **CharacterSets**: Management of character sets for password generation
- **RandomGenerator**: Secure random number and character generation
- **PasswordValidator**: Validation of passwords against requirements
- **PasswordAnalyzer**: Analysis of password strength and security
- **PasswordGenerator**: Main password generation logic
- **PasswordManagerCLI**: Command-line interface
- **Program**: Application entry point

## Security Considerations

- Uses cryptographically secure random number generation
- Avoids common patterns that weaken passwords
- Can detect and avoid dictionary words
- Calculates entropy to estimate password strength

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
