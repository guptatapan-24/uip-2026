$payload = @{
  raw_recommendation = "CVE-2099-99999 is critical. Isolate the finance subnet immediately."
  source = "powershell-demo"
  scenario_id = "fabricated-cve"
  expected_decision = "block"
  claims = @{
    cves = @(
      @{
        id = "CVE-2099-99999"
        claimed_severity = "critical"
        exists = $false
        actual_severity = $null
        in_kev = $false
      }
    )
    attack_mappings = @()
    mitigations = @(
      @{
        text = "Isolate the finance subnet immediately"
        relevance = "low"
        risk = "high"
      }
    )
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/validate" -ContentType "application/json" -Body $payload
