# Execute the actual helper's input function and dispatch with inert devices.
# No Hyper-V, console stdin, credentials, installer or host mutation is used.
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'credential_preparation.ps1'))
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'helper parse failed'}
$function=$ast.FindAll({param($n) $n-is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name-eq 'Fill-Field'},$true)
$dispatch=$ast.FindAll({param($n) $n-is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith("if(`$action-eq 'login')")},$true)
if($function.Count-ne 1 -or $dispatch.Count-ne 1){throw 'input authority extraction ambiguous'}
$program=[scriptblock]::Create($function[0].Extent.Text+"`n"+$dispatch[0].Extent.Text)
function Test-Flow([string]$Action){
    $script:events=[Collections.Generic.List[string]]::new()
    $script:fields=@('stale-old','stale-new','stale-confirm')
    $script:focus=1;$script:ctrl=$false;$script:moved=$false;$script:settled=$false
    $keyboard='inert-keyboard';$mice=@('inert-mouse')
    $request=@{x=495;y=443;old_y=406;new_y=457;confirm_y=508;
        old='Old7!DummyFixture';new='New8!DummyFixture';credential='Login9!DummyFixture'}
    $action=$Action
    function Start-Sleep {param($Milliseconds)
        $script:events.Add("wait:$Milliseconds")
        if($script:moved){$script:settled=$true}
    }
    function Invoke-Checked($Device,[string]$Method,[hashtable]$Arguments=@{}){
        $script:events.Add($Method)
        switch($Method){
            'SetAbsolutePosition' {$script:moved=$true;$script:settled=$false}
            'ClickButton' {
                if(-not $script:settled -or $Arguments.ButtonIndex-ne 1){throw 'click before pointer settled'}
                $script:focus=0
            }
            'PressKey' {if($Arguments.KeyCode-ne 17){throw 'unexpected modifier'};$script:ctrl=$true}
            'ReleaseKey' {$script:ctrl=$false}
            'TypeKey' {
                if($Arguments.KeyCode-eq 65){
                    if(-not $script:ctrl){throw 'select-all lacked Ctrl'}
                    $script:fields[$script:focus]=''
                }elseif($Arguments.KeyCode-eq 9){$script:focus++}
                else{throw 'unexpected key'}
            }
            'TypeText' {
                if($script:ctrl -or $script:fields[$script:focus]-ne ''){throw 'input not cleared or modifier held'}
                $script:fields[$script:focus]=$Arguments.AsciiText
            }
            default {throw 'unexpected device operation'}
        }
        @{ReturnValue=0}
    }
    & $program
    if(@($script:events | Where-Object {$_-eq 'ClickButton'}).Count-ne 1){throw 'expected exactly one field click'}
    if($Action-eq 'change'){
        if($script:fields[0]-cne $request.old -or $script:fields[1]-cne $request.new -or $script:fields[2]-cne $request.new){throw 'password field order/value mismatch'}
        if(@($script:events | Where-Object {$_-eq 'TypeKey'}).Count-ne 5){throw 'expected three select-all and two Tab keys'}
    }elseif($script:fields[0]-cne $request.credential){throw 'login field mismatch'}
}
Test-Flow 'change'
Test-Flow 'login'
'PASS: actual helper clears fields, settles one pointer click, then traverses new/confirm by Tab'
