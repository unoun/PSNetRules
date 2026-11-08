#Requires -Version 7

Measure-PSComplexity -Path ./src | Sort-Object Cognitive -Descending |
Format-Table File, Unit, Line, Cyclomatic, Cognitive

if (-not (Test-PSComplexity -Path ./src)) {
    throw 'Complexity gate failed'
}