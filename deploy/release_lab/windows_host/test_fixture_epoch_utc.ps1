# Actual two canonical expressions; no app, process query, guest, network or timezone change.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$sources=@((Join-Path $PSScriptRoot 'hyperv_adapter.ps1'),(Join-Path (Split-Path $PSScriptRoot -Parent) 'windows_netstack_fixture\adapter_action.ps1'))
$expected=[long]1793296800123456700;$remainder=[long]0
$unixTicks=[Math]::DivRem($expected,[long]100,[ref]$remainder)
if($remainder-ne0){throw 'test instant is off the100nsgrid'}
$utc=[DateTime]::new(([long]621355968000000000+$unixTicks),[DateTimeKind]::Utc)
$checks=0
foreach($source in $sources){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'canonical fixture source parse failed'}
 $assignments=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left.Extent.Text-eq'$start'-and$n.Right.Extent.Text.Contains('1970-01-01T00:00:00Z')-and$n.Right.Extent.Text.Contains('StartTime')},$true))
 if($assignments.Count-ne1){throw 'unique actual fixture epoch expression required'}
 $node=$assignments[0]
 $epochUTC=@($node.FindAll({param($n)$n-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$n.Member.Extent.Text-eq'ToUniversalTime'-and$n.Expression-is[Management.Automation.Language.ParenExpressionAst]-and@($n.Expression.FindAll({param($c)$c-is[Management.Automation.Language.ConvertExpressionAst]-and$c.Type.TypeName.FullName-eq'DateTime'-and$c.Child.Extent.Text-eq"'1970-01-01T00:00:00Z'"},$true)).Count-eq1},$true))
 if($epochUTC.Count-ne1){throw 'fixture epoch is not explicitly converted toUTC (also reject old source onUTC hosts)'}
 foreach($instant in @($utc,$utc.ToLocalTime())){
  $actual=[pscustomobject]@{StartTime=$instant}
  $result=&([scriptblock]::Create('param($actual);'+$node.Extent.Text+';return $start')) $actual
  if($result-isnot[long]-or$result-ne$expected){throw 'actual fixture expression lost UTC identity or Int64 precision'}
  $checks++
 }
}
[ordered]@{status='PASS';actualSourceExpressions=2;checks=$checks;localZone=[TimeZoneInfo]::Local.Id;processesStarted=$false;timezoneChanged=$false}|ConvertTo-Json -Compress
