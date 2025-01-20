# Brutus Brute Forcer v2.0

A fast, concurrent brute force tool for FTP and Web lopgin boxes (Auth boxes from webserrvers) written in Go.

⚠️ **Legal Disclaimer**: This tool is for educational and authorized testing only.

## Features

- Concurrent password attacks
- Rate limiting per target
- FTP and web login support  
- Colorized output with verbose logging
- Automatic updates
- Progress tracking and statistics

## Installation

```bash
go install github.com/fernstedt/brutus@latest
```

Or clone manually:
```bash
git clone https://github.com/fernstedt/brutus.git
cd brutus
go install
```

## Usage
### Parameters

- `-ftp`: Target FTP server (IP:port)
- `-web`: Target web login URL
- `-username`: Username for login attempts  
- `-wordlist`: Path to password list
- `-threads`: Concurrent threads (default: 10)
- `-rate`: Rate limit per second (default: 20)
- `-verbose`: Enable detailed output

### Examples

FTP:
```bash
brutus -ftp 192.168.1.100:21 -username admin -wordlist passwords.txt
```

Web:
```bash 
brutus -web http://example.com/login/ -username admin -wordlist passwords.txt -rate 10
```

### Output

- Successful logins: `successful_logins.txt`
- Debug logs: `app.log`
- Real-time statistics on completion

### Update

```bash
brutus update
```
