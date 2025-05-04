namespace PasswordGenerator

open System
open System.Security.Cryptography
open System.Text.RegularExpressions
open System.IO
open System.Collections.Generic

/// Module containing configuration types and utility functions
module Config =
    /// Password strength levels
    type PasswordStrength =
        | Basic
        | Medium
        | Strong
        | VeryStrong
        | Custom
        
    /// Password generation rules
    type PasswordRules = {
        Length: int
        IncludeUppercase: bool
        IncludeLowercase: bool
        IncludeNumbers: bool
        IncludeSpecialChars: bool
        ExcludeSimilarChars: bool
        ExcludeAmbiguousChars: bool
        MinUppercase: int option
        MinLowercase: int option
        MinNumbers: int option
        MinSpecialChars: int option
        CustomCharset: string option
        AvoidRepeatedChars: bool
        AvoidSequentialChars: bool
        AvoidDictionaryWords: bool
    }
    
    /// Default password rules
    let DefaultRules = {
        Length = 12
        IncludeUppercase = true
        IncludeLowercase = true
        IncludeNumbers = true
        IncludeSpecialChars = true
        ExcludeSimilarChars = false
        ExcludeAmbiguousChars = false
        MinUppercase = None
        MinLowercase = None
        MinNumbers = None
        MinSpecialChars = None
        CustomCharset = None
        AvoidRepeatedChars = false
        AvoidSequentialChars = false
        AvoidDictionaryWords = false
    }
    
    /// Get predefined rules based on password strength
    let getRulesForStrength strength =
        match strength with
        | Basic -> 
            { DefaultRules with 
                Length = 8
                IncludeSpecialChars = false
                IncludeUppercase = true
                IncludeLowercase = true
                IncludeNumbers = true
            }
        | Medium -> 
            { DefaultRules with 
                Length = 10
                IncludeSpecialChars = true
                MinNumbers = Some 2
                MinUppercase = Some 1
            }
        | Strong -> 
            { DefaultRules with 
                Length = 14
                IncludeSpecialChars = true
                MinNumbers = Some 2
                MinUppercase = Some 2
                MinSpecialChars = Some 2
                AvoidRepeatedChars = true
            }
        | VeryStrong -> 
            { DefaultRules with 
                Length = 18
                IncludeSpecialChars = true
                MinNumbers = Some 3
                MinUppercase = Some 3
                MinSpecialChars = Some 3
                AvoidRepeatedChars = true
                AvoidSequentialChars = true
                AvoidDictionaryWords = true
                ExcludeSimilarChars = true
            }
        | Custom -> DefaultRules

/// Module for character set management
module CharacterSets =
    let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let lowercase = "abcdefghijklmnopqrstuvwxyz"
    let numbers = "0123456789"
    let specialChars = "!@#$%^&*()-_=+[]{};:,.<>/?|~"
    let similarChars = "il1IoO0"
    let ambiguousChars = "{}[]()/\\'\"`~,;:.<>"
    
    /// Remove characters from a string
    let removeChars (source: string) (charsToRemove: string) =
        String.filter (fun c -> not (charsToRemove.Contains(c.ToString()))) source
    
    /// Build character set based on rules
    let buildCharSet (rules: Config.PasswordRules) =
        match rules.CustomCharset with
        | Some charset -> charset
        | None ->
            let mutable charSet = ""
            
            if rules.IncludeUppercase then
                charSet <- charSet + uppercase
            
            if rules.IncludeLowercase then
                charSet <- charSet + lowercase
                
            if rules.IncludeNumbers then
                charSet <- charSet + numbers
                
            if rules.IncludeSpecialChars then
                charSet <- charSet + specialChars
                
            if rules.ExcludeSimilarChars then
                charSet <- removeChars charSet similarChars
                
            if rules.ExcludeAmbiguousChars then
                charSet <- removeChars charSet ambiguousChars
                
            charSet

/// Module for secure random generation
module RandomGenerator =
    /// Generate a cryptographically secure random number
    let getSecureRandomNumber max =
        use provider = RandomNumberGenerator.Create()
        let scale = uint32 max
        
        // Handle case where max is 0
        if scale = 0u then 0
        else
            let buffer = Array.zeroCreate<byte> 4
            let mutable result = UInt32.MaxValue
            
            // Keep generating until we find a value within range
            while result >= scale do
                provider.GetBytes(buffer)
                result <- BitConverter.ToUInt32(buffer, 0) % scale
                
            int result
    
    /// Select a random character from a string
    let getRandomChar (charSet: string) =
        let index = getSecureRandomNumber charSet.Length
        charSet.[index]
    
    /// Shuffle a string using Fisher-Yates algorithm
    let shuffleString (input: string) =
        let chars = input.ToCharArray()
        let len = chars.Length
        
        // Fisher-Yates shuffle
        for i in [0..len-2] do
            let j = i + getSecureRandomNumber (len - i)
            let temp = chars.[i]
            chars.[i] <- chars.[j]
            chars.[j] <- temp
            
        new String(chars)

/// Module for password validation
module PasswordValidator =
    open Config
    
    /// Common dictionary words for password validation
    let commonWords = [
        "password"; "123456"; "qwerty"; "admin"; "welcome";
        "letmein"; "monkey"; "abc123"; "starwars"; "login";
        "dragon"; "master"; "football"; "baseball"; "access"
    ]
    
    /// Load additional dictionary words from file if available
    let loadDictionaryWords filePath =
        if File.Exists(filePath) then
            try
                File.ReadAllLines(filePath) |> Array.toList
            with
            | _ -> commonWords
        else
            commonWords
    
    /// Check if a password contains sequential characters
    let containsSequentialChars (password: string) =
        let sequences = [
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "zyxwvutsrqponmlkjihgfedcba"
            "ZYXWVUTSRQPONMLKJIHGFEDCBA"
            "9876543210"
        ]
        
        sequences 
        |> List.exists (fun seq -> 
            seq |> Seq.windowed 3 
                |> Seq.map String.Concat
                |> Seq.exists (fun triplet -> password.Contains(triplet))
        )
    
    /// Check if a password contains dictionary words
    let containsDictionaryWord (password: string) =
        let passwordLower = password.ToLower()
        
        let dictionaryWords = 
            try
                loadDictionaryWords "dictionary.txt"
            with
            | _ -> commonWords
            
        dictionaryWords
        |> List.exists (fun word -> 
            word.Length > 3 && passwordLower.Contains(word.ToLower())
        )
    
    /// Check if a password contains repeated characters
    let containsRepeatedChars (password: string) =
        password
        |> Seq.windowed 3
        |> Seq.exists (fun window -> 
            window.[0] = window.[1] && window.[1] = window.[2]
        )
    
    /// Count specific character types in a password
    let countCharTypes (password: string) =
        let uppercase = Regex(@"[A-Z]")
        let lowercase = Regex(@"[a-z]")
        let numbers = Regex(@"[0-9]")
        let specialChars = Regex(@"[^a-zA-Z0-9]")
        
        {|
            UppercaseCount = uppercase.Matches(password).Count
            LowercaseCount = lowercase.Matches(password).Count
            NumberCount = numbers.Matches(password).Count
            SpecialCharCount = specialChars.Matches(password).Count
        |}
    
    /// Check if a password meets all requirements
    let passwordMeetsRequirements (password: string) (rules: PasswordRules) =
        let counts = countCharTypes password
        
        // Character type requirements
        let meetsMinUppercase = 
            match rules.MinUppercase with 
            | Some min -> counts.UppercaseCount >= min
            | None -> true
            
        let meetsMinLowercase = 
            match rules.MinLowercase with 
            | Some min -> counts.LowercaseCount >= min
            | None -> true
            
        let meetsMinNumbers = 
            match rules.MinNumbers with 
            | Some min -> counts.NumberCount >= min
            | None -> true
            
        let meetsMinSpecialChars = 
            match rules.MinSpecialChars with 
            | Some min -> counts.SpecialCharCount >= min
            | None -> true
        
        // Additional requirements
        let meetsRepeatedCharsRule =
            not rules.AvoidRepeatedChars || not (containsRepeatedChars password)
            
        let meetsSequentialCharsRule =
            not rules.AvoidSequentialChars || not (containsSequentialChars password)
            
        let meetsDictionaryWordsRule =
            not rules.AvoidDictionaryWords || not (containsDictionaryWord password)
        
        // All requirements must be met
        meetsMinUppercase && 
        meetsMinLowercase && 
        meetsMinNumbers && 
        meetsMinSpecialChars &&
        meetsRepeatedCharsRule &&
        meetsSequentialCharsRule &&
        meetsDictionaryWordsRule

/// Module for analyzing password strength
module PasswordAnalyzer =
    /// Result of password strength analysis
    type PasswordAnalysisResult = {
        EntropyBits: float
        CrackTimeEstimate: string
        Suggestions: string list
        StrengthScore: int  // 1-5
    }
    
    /// Calculate entropy bits for a password
    let calculateEntropyBits (password: string) =
        // Get character pool size based on characters used
        let hasUppercase = password |> Seq.exists Char.IsUpper
        let hasLowercase = password |> Seq.exists Char.IsLower
        let hasDigits = password |> Seq.exists Char.IsDigit
        let hasSpecial = password |> Seq.exists (fun c -> 
            not (Char.IsLetterOrDigit(c)))
        
        let poolSize =
            (if hasUppercase then 26 else 0) +
            (if hasLowercase then 26 else 0) +
            (if hasDigits then 10 else 0) +
            (if hasSpecial then 33 else 0)
        
        let length = float password.Length
        let entropy = length * (Math.Log(float poolSize) / Math.Log(2.0))
        
        entropy
    
    /// Estimate password crack time
    let estimateCrackTime entropyBits =
        // Assume 10 billion guesses per second (high-end hardware)
        let guessesPerSecond = 10.0 ** 10.0
        let secondsToCrack = (2.0 ** entropyBits) / guessesPerSecond
        
        if secondsToCrack < 1.0 then
            "Instantly"
        elif secondsToCrack < 60.0 then
            sprintf "%.1f seconds" secondsToCrack
        elif secondsToCrack < 3600.0 then
            sprintf "%.1f minutes" (secondsToCrack / 60.0)
        elif secondsToCrack < 86400.0 then
            sprintf "%.1f hours" (secondsToCrack / 3600.0)
        elif secondsToCrack < 31536000.0 then
            sprintf "%.1f days" (secondsToCrack / 86400.0)
        elif secondsToCrack < 31536000.0 * 100.0 then
            sprintf "%.1f years" (secondsToCrack / 31536000.0)
        elif secondsToCrack < 31536000.0 * 1000.0 then
            sprintf "%.1f centuries" (secondsToCrack / (31536000.0 * 100.0))
        else
            "Millions of years or more"
    
    /// Generate improvement suggestions for a password
    let generateSuggestions (password: string) =
        let suggestions = new List<string>()
        
        if password.Length < 12 then
            suggestions.Add("Consider using a longer password (12+ characters)")
        
        if not (password |> Seq.exists Char.IsUpper) then
            suggestions.Add("Add uppercase letters")
            
        if not (password |> Seq.exists Char.IsLower) then
            suggestions.Add("Add lowercase letters")
            
        if not (password |> Seq.exists Char.IsDigit) then
            suggestions.Add("Add numbers")
            
        if not (password |> Seq.exists (fun c -> not (Char.IsLetterOrDigit(c)))) then
            suggestions.Add("Add special characters")
        
        if PasswordValidator.containsSequentialChars password then
            suggestions.Add("Avoid sequential characters (e.g., '123', 'abc')")
            
        if PasswordValidator.containsDictionaryWord password then
            suggestions.Add("Avoid common dictionary words")
            
        if PasswordValidator.containsRepeatedChars password then
            suggestions.Add("Avoid repeated characters (e.g., 'aaa')")
            
        suggestions |> List.ofSeq
    
    /// Calculate strength score on a scale of 1-5
    let calculateStrengthScore (entropyBits: float) =
        if entropyBits < 28.0 then 1       // Very weak
        elif entropyBits < 36.0 then 2     // Weak
        elif entropyBits < 60.0 then 3     // Medium
        elif entropyBits < 80.0 then 4     // Strong
        else 5                             // Very strong
    
    /// Analyze password strength
    let analyzePassword (password: string) =
        let entropyBits = calculateEntropyBits password
        let crackTimeEstimate = estimateCrackTime entropyBits
        let suggestions = generateSuggestions password
        let strengthScore = calculateStrengthScore entropyBits
        
        {
            EntropyBits = entropyBits
            CrackTimeEstimate = crackTimeEstimate
            Suggestions = suggestions
            StrengthScore = strengthScore
        }

/// Main password generation module
module PasswordGenerator =
    open Config
    
    /// Strategy for ensuring minimum character requirements
    type MinRequirementStrategy =
        | PlaceAtRandom
        | PlaceAtBeginning
        | PlaceAtEnd
    
    /// Generate a basic password without additional requirements
    let generateBasicPassword (charSet: string) (length: int) =
        if String.IsNullOrEmpty(charSet) || length <= 0 then ""
        else
            [1..length]
            |> List.map (fun _ -> RandomGenerator.getRandomChar charSet)
            |> List.toArray
            |> String
    
    /// Ensure minimum character requirements are met
    let ensureMinimumRequirements (password: string) (rules: PasswordRules) (strategy: MinRequirementStrategy) =
        let mutable resultPassword = password
        let mutable requiredChars = []
        
        // Add required uppercase characters
        match rules.MinUppercase with
        | Some min ->
            let currentCount = resultPassword |> Seq.filter Char.IsUpper |> Seq.length
            if currentCount < min then
                for _ in 1..(min - currentCount) do
                    requiredChars <- RandomGenerator.getRandomChar CharacterSets.uppercase :: requiredChars
        | None -> ()
        
        // Add required lowercase characters
        match rules.MinLowercase with
        | Some min ->
            let currentCount = resultPassword |> Seq.filter Char.IsLower |> Seq.length
            if currentCount < min then
                for _ in 1..(min - currentCount) do
                    requiredChars <- RandomGenerator.getRandomChar CharacterSets.lowercase :: requiredChars
        | None -> ()
        
        // Add required number characters
        match rules.MinNumbers with
        | Some min ->
            let currentCount = resultPassword |> Seq.filter Char.IsDigit |> Seq.length
            if currentCount < min then
                for _ in 1..(min - currentCount) do
                    requiredChars <- RandomGenerator.getRandomChar CharacterSets.numbers :: requiredChars
        | None -> ()
        
        // Add required special characters
        match rules.MinSpecialChars with
        | Some min ->
            let currentCount = resultPassword |> Seq.filter (fun c -> not (Char.IsLetterOrDigit(c))) |> Seq.length
            if currentCount < min then
                for _ in 1..(min - currentCount) do
                    requiredChars <- RandomGenerator.getRandomChar CharacterSets.specialChars :: requiredChars
        | None -> ()
        
        // If we have characters to add, handle according to strategy
        if not requiredChars.IsEmpty then
            match strategy with
            | PlaceAtRandom ->
                // Convert password to char array for manipulation
                let passwordChars = resultPassword.ToCharArray()
                
                // Replace random positions with required characters
                for requiredChar in requiredChars do
                    let mutable positionFound = false
                    while not positionFound do
                        let position = RandomGenerator.getSecureRandomNumber passwordChars.Length
                        // Don't replace characters we already added
                        if passwordChars.[position] <> requiredChar then
                            passwordChars.[position] <- requiredChar
                            positionFound <- true
                
                resultPassword <- new String(passwordChars)
                
            | PlaceAtBeginning ->
                resultPassword <- String.Concat(requiredChars) + resultPassword.Substring(requiredChars.Length)
                // Shuffle to avoid predictable pattern
                resultPassword <- RandomGenerator.shuffleString resultPassword
                
            | PlaceAtEnd ->
                let startPart = resultPassword.Substring(0, resultPassword.Length - requiredChars.Length)
                resultPassword <- startPart + String.Concat(requiredChars)
                // Shuffle to avoid predictable pattern
                resultPassword <- RandomGenerator.shuffleString resultPassword
        
        resultPassword
    
    /// Generate a password that meets all requirements
    let rec generateCompliantPassword (rules: PasswordRules) (maxAttempts: int) (attempt: int) =
        if attempt >= maxAttempts then
            failwith "Failed to generate a compliant password after maximum attempts"
        
        let charSet = CharacterSets.buildCharSet rules
        let basicPassword = generateBasicPassword charSet rules.Length
        
        let passwordWithRequirements = 
            ensureMinimumRequirements basicPassword rules MinRequirementStrategy.PlaceAtRandom
        
        if PasswordValidator.passwordMeetsRequirements passwordWithRequirements rules then
            passwordWithRequirements
        else
            generateCompliantPassword rules maxAttempts (attempt + 1)
    
    /// Generate a password with the specified rules
    let generatePassword (rules: PasswordRules) =
        try
            generateCompliantPassword rules 100 0
        with
        | ex -> failwithf "Password generation failed: %s" ex.Message

/// Main CLI interface module
module PasswordManagerCLI =
    open Config
    
    /// Command line options
    type CLIOptions = {
        Strength: PasswordStrength
        GenerateMultiple: int
        SaveToFile: string option
        AnalyzeMode: bool
        PasswordToAnalyze: string option
        CustomLength: int option
        CustomRules: PasswordRules option
        Help: bool
    }
    
    /// Default CLI options
    let defaultOptions = {
        Strength = Medium
        GenerateMultiple = 1
        SaveToFile = None
        AnalyzeMode = false
        PasswordToAnalyze = None
        CustomLength = None
        CustomRules = None
        Help = false
    }
    
    /// Parse command line arguments
    let parseCommandLine (args: string[]) =
        let rec parseArgs (options: CLIOptions) (args: string list) =
            match args with
            | [] -> options
            | "--strength" :: value :: rest ->
                let strength = 
                    match value.ToLower() with
                    | "basic" -> Basic
                    | "medium" -> Medium
                    | "strong" -> Strong
                    | "verystrong" -> VeryStrong
                    | "custom" -> Custom
                    | _ -> options.Strength
                parseArgs { options with Strength = strength } rest
                
            | "--count" :: value :: rest ->
                match Int32.TryParse(value) with
                | true, count when count > 0 -> 
                    parseArgs { options with GenerateMultiple = count } rest
                | _ -> parseArgs options rest
                
            | "--output" :: value :: rest ->
                parseArgs { options with SaveToFile = Some value } rest
                
            | "--analyze" :: rest ->
                parseArgs { options with AnalyzeMode = true } rest
                
            | "--password" :: value :: rest ->
                parseArgs { options with PasswordToAnalyze = Some value } rest
                
            | "--length" :: value :: rest ->
                match Int32.TryParse(value) with
                | true, length when length > 0 -> 
                    parseArgs { options with CustomLength = Some length } rest
                | _ -> parseArgs options rest
                
            | "--help" :: rest ->
                parseArgs { options with Help = true } rest
                
            | _ :: rest -> 
                parseArgs options rest
        
        parseArgs defaultOptions (Array.toList args)
    
    /// Display help information
    let displayHelp() =
        printfn "F# Password Generator"
        printfn "Usage: PasswordGenerator [options]"
        printfn ""
        printfn "Options:"
        printfn "  --strength <value>    Set password strength (basic, medium, strong, verystrong, custom)"
        printfn "  --count <value>       Number of passwords to generate"
        printfn "  --length <value>      Custom password length"
        printfn "  --output <filename>   Save generated passwords to file"
        printfn "  --analyze             Analyze password strength"
        printfn "  --password <value>    Password to analyze"
        printfn "  --help                Display this help message"
    
    /// Save passwords to file
    let savePasswordsToFile (passwords: string list) (filename: string) =
        try
            File.WriteAllLines(filename, passwords)
            printfn "Passwords saved to %s" filename
            true
        with
        | ex ->
            printfn "Error saving passwords to file: %s" ex.Message
            false
    
    /// Display password analysis
    let displayAnalysis (password: string) =
        let analysis = PasswordAnalyzer.analyzePassword password
        
        printfn "\nPassword Analysis:"
        printfn "-------------------"
        printfn "Password: %s" password
        printfn "Entropy: %.2f bits" analysis.EntropyBits
        printfn "Estimated crack time: %s" analysis.CrackTimeEstimate
        
        printfn "\nStrength: %s" (
            match analysis.StrengthScore with
            | 1 -> "Very Weak"
            | 2 -> "Weak"
            | 3 -> "Medium"
            | 4 -> "Strong"
            | 5 -> "Very Strong"
            | _ -> "Unknown"
        )
        
        if analysis.Suggestions.Length > 0 then
            printfn "\nSuggestions for improvement:"
            analysis.Suggestions
            |> List.iteri (fun i suggestion ->
                printfn " %d. %s" (i + 1) suggestion
            )
        else
            printfn "\nNo suggestions for improvement."
    
    /// Run the CLI
    let run (args: string[]) =
        let options = parseCommandLine args
        
        if options.Help then
            displayHelp()
            0
        elif options.AnalyzeMode then
            match options.PasswordToAnalyze with
            | Some password ->
                displayAnalysis password
                0
            | None ->
                printfn "Error: No password provided for analysis. Use --password <value>"
                1
        else
            try
                // Determine which rules to use
                let baseRules = getRulesForStrength options.Strength
                
                // Apply custom length if specified
                let rules =
                    match options.CustomLength with
                    | Some length -> { baseRules with Length = length }
                    | None -> baseRules
                
                // Apply custom rules if provided
                let finalRules =
                    match options.CustomRules with
                    | Some customRules -> customRules
                    | None -> rules
                
                // Generate passwords
                let passwords =
                    [1..options.GenerateMultiple]
                    |> List.map (fun _ -> PasswordGenerator.generatePassword finalRules)
                
                // Display generated passwords
                printfn "\nGenerated %d password(s):" options.GenerateMultiple
                passwords |> List.iteri (fun i pwd -> printfn "[%d]: %s" (i + 1) pwd)
                
                // Save to file if requested
                match options.SaveToFile with
                | Some filename -> 
                    savePasswordsToFile passwords filename |> ignore
                | None -> ()
                
                // Analyze the first password
                if options.GenerateMultiple > 0 then
                    displayAnalysis passwords.[0]
                
                0
            with
            | ex ->
                printfn "Error: %s" ex.Message
                1

