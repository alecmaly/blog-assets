# variables
$output_filepath = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path + "\hacktivity_data_$(get-date -f "yyyyMMdd").csv"
# end variables

# functions
Function Flatten-Object {                                       # Version 00.02.12, by iRon
    [CmdletBinding()]Param (
        [Parameter(ValueFromPipeLine = $True)][Object[]]$Objects,
        [String]$Separator = ".", [ValidateSet("", 0, 1)]$Base = 1, [Int]$Depth = 5, [Int]$Uncut = 1,
        [String[]]$ToString = ([String], [DateTime], [TimeSpan]), [String[]]$Path = @()
    )
    $PipeLine = $Input | ForEach {$_}; If ($PipeLine) {$Objects = $PipeLine}
    If (@(Get-PSCallStack)[1].Command -eq $MyInvocation.MyCommand.Name -or @(Get-PSCallStack)[1].Command -eq "<position>") {
        $Object = @($Objects)[0]; $Iterate = New-Object System.Collections.Specialized.OrderedDictionary
        If ($ToString | Where {$Object -is $_}) {$Object = $Object.ToString()}
        ElseIf ($Depth) {$Depth--
            If ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IDictionaryEnumerator[\W]") {
                $Iterate = $Object
            } ElseIf ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IEnumerator[\W]") {
                $Object.GetEnumerator() | ForEach -Begin {$i = $Base} {$Iterate.($i) = $_; $i += 1}
            } Else {
                $Names = If ($Uncut) {$Uncut--} Else {$Object.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames}
                If (!$Names) {$Names = $Object.PSObject.Properties | Where {$_.IsGettable} | Select -Expand Name}
                If ($Names) {$Names | ForEach {$Iterate.$_ = $Object.$_}}
            }
        }
        If (@($Iterate.Keys).Count) {
            $Iterate.Keys | ForEach {
                Flatten-Object @(,$Iterate.$_) $Separator $Base $Depth $Uncut $ToString ($Path + $_)
            }
        }  Else {$Property.(($Path | Where {$_}) -Join $Separator) = $Object}
    } ElseIf ($Objects -ne $Null) {
        @($Objects) | ForEach -Begin {$Output = @(); $Names = @()} {
            New-Variable -Force -Option AllScope -Name Property -Value (New-Object System.Collections.Specialized.OrderedDictionary)
            Flatten-Object @(,$_) $Separator $Base $Depth $Uncut $ToString $Path
            $Output += New-Object PSObject -Property $Property
            $Names += $Output[-1].PSObject.Properties | Select -Expand Name
        }
        $Output | Select ([String[]]($Names | Select -Unique))
    }
}
# end functions


$query = '
query {
	hacktivity_items(
    	# first: 100											# return first X results
    	after: "__CURSOR_VAL__"								# after cursor
    	where:{
        report: {
          # id: { _eq: 1087489 },										# filter for specific report
          # hacker_published: { _eq: true },				# show only externally published reports
          disclosed_at: { _is_null: false }					# show only disclosed reports
        }
      }, 					
  		order_by: { field: popular, direction: DESC }  	    # sort by most popular
		) {
		total_count
		pageInfo {
			hasNextPage
		}
		edges {
			cursor
		}
		nodes {
      ... on HackerPublished {
        __typename
        HackerPublished:report {
          _id
          title
          severity {
            rating
            score
          }
          bounties {
            total_awarded_amount
          }
          disclosed_at
        }
        votes {
          total_count
        }
        team {
          handle
          reports_received_last_90_days
        }
			}
			... on Disclosed {
        __typename
        currency
        Disclosed:report {
          _id
          title
          severity {
            rating
            score
          }
          bounties {
            total_awarded_amount
          }
          team {
            handle
            reports_received_last_90_days
          }
          disclosed_at
        }
        votes {
          total_count
        }
			}
		}

	}
}
'

$headers = @{}
$headers.Add('Content-Type', 'application/json')
$headers.Add('Accept', 'application/json')

rm $output_filepath -ErrorAction SilentlyContinue
$next_query = $query.Replace('__CURSOR_VAL__', '')
$counter = 0
do {  
    # TO DO: try / catch to retry if failed.... due to throttling
    Write-Host "[+] Querying next page of info..."
    $resp = Invoke-RestMethod -Method Post -Uri 'https://hackerone.com/graphql' -Headers $headers -Body (@{'query'= $next_query} | ConvertTo-Json) 
    $next_query = $query.Replace('__CURSOR_VAL__', ($resp.data.hacktivity_items.edges | select -last 1).cursor)

    foreach ($node in $resp.data.hacktivity_items.nodes) {
        $obj = Flatten-Object $node
        $obj | Add-Member NoteProperty -Name "URL" -Value "https://hackerone.com/reports/$($node.Disclosed._id)"
        $obj | Export-Csv $output_filepath -NoTypeInformation -Append -Force
    }

    $counter += $resp.data.hacktivity_items.nodes.count
    write-host $counter / $($resp.data.hacktivity_items.total_count)
} while ($resp.data.hacktivity_items.pageInfo.hasNextPage)


Write-Host "[+] Done."
Write-Host "[+] Output File:`t$($output_filepath)"