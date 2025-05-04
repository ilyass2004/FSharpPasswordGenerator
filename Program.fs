module Program

open PasswordGenerator

[<EntryPoint>]
let main args =
    PasswordManagerCLI.run args