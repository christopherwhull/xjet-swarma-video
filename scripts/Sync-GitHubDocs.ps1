#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$PandocPath = 'pandoc'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$pages = [ordered]@{
    'index.html' = 'docs/overview.md'
    'docs/design.html' = 'docs/design.md'
    'docs/video-comparison.html' = 'docs/video-comparison.md'
}
$pandoc = Get-Command $PandocPath -ErrorAction SilentlyContinue
if (-not $pandoc) {
    throw 'Pandoc is required. Install it from https://pandoc.org/installing.html or pass -PandocPath.'
}

foreach ($source in $pages.Keys) {
    $document = [System.Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.Load((Join-Path $repoRoot $source))

    # Pandoc retains div identifiers but discards paragraph identifiers.
    foreach ($paragraph in @($document.SelectNodes('//p[@id]'))) {
        $wrapper = $document.CreateElement('div')
        $wrapper.SetAttribute('id', $paragraph.GetAttribute('id'))
        $paragraph.RemoveAttribute('id')
        [void]$paragraph.ParentNode.ReplaceChild($wrapper, $paragraph)
        [void]$wrapper.AppendChild($paragraph)
    }

    # Resolve links from the source location, then target the Markdown sibling.
    foreach ($link in $document.SelectNodes('//a[@href]')) {
        $href = $link.GetAttribute('href')
        if ($href -match '^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//|#)') { continue }
        $parts = $href -split '#', 2
        $sourceDirectory = Split-Path (Join-Path $repoRoot $source) -Parent
        $target = [System.IO.Path]::GetFullPath((Join-Path $sourceDirectory $parts[0]))
        $relative = [System.IO.Path]::GetRelativePath($repoRoot, $target).Replace('\', '/')
        if ($pages.Contains($relative)) { $target = Join-Path $repoRoot $pages[$relative] }
        $outputDirectory = Split-Path (Join-Path $repoRoot $pages[$source]) -Parent
        $rewritten = [System.IO.Path]::GetRelativePath($outputDirectory, $target).Replace('\', '/')
        if ($parts.Count -eq 2) { $rewritten += '#' + $parts[1] }
        $link.SetAttribute('href', $rewritten)
    }

    # Pandoc treats figures as raw HTML. Replace CSS flows with readable paragraphs,
    # retaining every box, direction arrow, lane label, and caption in source order.
    foreach ($figure in @($document.SelectNodes('//figure'))) {
        $replacement = $document.CreateElement('div')
        foreach ($child in $figure.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $paragraph = $document.CreateElement('p')
            if ($child.GetAttribute('class') -eq 'flow') {
                foreach ($item in $child.ChildNodes) {
                    if ($item.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                    if ($item.GetAttribute('class') -eq 'box') {
                        foreach ($label in $item.ChildNodes) {
                            if ($label.Name -eq 'span') {
                                [void]$paragraph.AppendChild($document.CreateTextNode(' — '))
                            }
                            [void]$paragraph.AppendChild($label.CloneNode($true))
                        }
                    } else {
                        [void]$paragraph.AppendChild($document.CreateTextNode(' ' + $item.InnerText.Trim() + ' '))
                    }
                }
            } else {
                foreach ($item in $child.ChildNodes) {
                    [void]$paragraph.AppendChild($item.CloneNode($true))
                }
            }
            [void]$replacement.AppendChild($paragraph)
        }
        [void]$figure.ParentNode.ReplaceChild($replacement, $figure)
    }

    # CSS block spans need a word boundary after layout is removed.
    foreach ($span in $document.SelectNodes('//span[@class="refs"]')) {
        [void]$span.PrependChild($document.CreateTextNode(' '))
    }
    # GFM supports inline cells, not HTML row-header cells or paragraph blocks.
    foreach ($cell in @($document.SelectNodes('//tbody/tr/th'))) {
        $replacement = $document.CreateElement('td')
        $replacement.InnerXml = $cell.InnerXml
        [void]$cell.ParentNode.ReplaceChild($replacement, $cell)
    }
    foreach ($paragraph in @($document.SelectNodes('//td/p'))) {
        [void]$paragraph.ParentNode.InsertBefore($document.CreateTextNode(' '), $paragraph)
        while ($paragraph.HasChildNodes) {
            [void]$paragraph.ParentNode.InsertBefore($paragraph.FirstChild, $paragraph)
        }
        [void]$paragraph.ParentNode.RemoveChild($paragraph)
    }
    $temporary = [System.IO.Path]::GetTempFileName()
    $temporaryMarkdown = [System.IO.Path]::GetTempFileName()
    try {
        $document.Save($temporary)
        & $pandoc.Source --from=html --to=gfm --wrap=none `
            "--lua-filter=$(Join-Path $PSScriptRoot 'github-docs.lua')" `
            "--output=$temporaryMarkdown" $temporary
        if ($LASTEXITCODE -ne 0) { throw "Pandoc failed for $source." }
        # Read UTF-8 directly instead of relying on the Windows console code page.
        $converted = [System.IO.File]::ReadAllText($temporaryMarkdown)
        $sourceLink = [System.IO.Path]::GetRelativePath(
            (Split-Path (Join-Path $repoRoot $pages[$source]) -Parent),
            (Join-Path $repoRoot $source)
        ).Replace('\', '/')
        $notice = "> Generated from [$source]($sourceLink). Edit the HTML source, then run ``pwsh -NoProfile -File scripts/Sync-GitHubDocs.ps1`` from the repository root."
        $text = $notice + "`n`n" + $converted.Replace("`r`n", "`n").Trim() + "`n"
        [System.IO.File]::WriteAllText((Join-Path $repoRoot $pages[$source]), $text)
        Write-Host "Generated $($pages[$source])"
    } finally {
        Remove-Item -LiteralPath $temporary
        Remove-Item -LiteralPath $temporaryMarkdown
    }
}
