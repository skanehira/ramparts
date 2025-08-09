/*
 * MCP Config Risk Detection
 * Detects risky STDIO server definitions that execute inline or external code
 * via common shells/interpreters combined with dangerous flags/tokens.
 */

rule MCPConfigRisk
{
    meta:
        name = "MCP Config Risk"
        description = "STDIO server uses risky shell/interpreter with inline code or pipe to shell"
        severity = "CRITICAL"
        category = "command-injection,config-risk"
        author = "Ramparts Security Team"
        version = "1.0"

    strings:
        // Command executables we consider dangerous when paired with risky args
        $cmd_exec = /COMMAND:\s*(bash|sh|cmd|pwsh|powershell|python(\d+(\.\d+)?)?|node)\b/i

        // calc.exe alone is considered risky on Windows
        $calc_exec = /COMMAND:\s*calc\.exe\b/i

        // Risky inline-exec flags
        $arg_flag = /ARGS:\s*.*(-c|-e)\b/i

        // Risky tokens in arguments (network fetch, piping to shell, chain)
        $arg_tokens = /ARGS:\s*.*(curl|wget|base64|nc\s|telnet|\|\s*sh|\|\s*bash|&&)/i

    condition:
        // Either explicit risky exec with risky args, or calc.exe alone
        ($cmd_exec and ($arg_flag or $arg_tokens)) or $calc_exec
}


