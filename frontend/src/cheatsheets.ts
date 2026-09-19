// Reference cheatsheets for interactive TCP protocols. Each entry is a static
// list of commands a user can copy into a netcat session; nothing here sends
// traffic on its own.

export interface CheatsheetCommand {
  label: string;
  command: string;
  note?: string;
}

export interface CheatsheetGroup {
  name: string;
  commands: CheatsheetCommand[];
}

export interface Cheatsheet {
  id: string;
  title: string;
  protocol: string;
  port: string;
  summary: string;
  groups: CheatsheetGroup[];
}

export const CHEATSHEETS: Cheatsheet[] = [
  {
    id: 'ftp',
    title: 'FTP',
    protocol: 'FTP',
    port: '21 (control)',
    summary:
      'File Transfer Protocol. The control channel is plain text; data moves over a separate connection. Use PASV for passive mode behind NAT. Lines end with CRLF.',
    groups: [
      {
        name: 'Connect & authenticate',
        commands: [
          { label: 'Connect', command: 'nc ftp.example.com 21' },
          { label: 'Server greeting', command: '220 (vsFTPd 3.0.5)', note: 'server → client' },
          { label: 'Anonymous user', command: 'USER anonymous' },
          { label: 'Anonymous password', command: 'PASS user@example.com', note: 'email is conventional' },
          { label: 'Login as a user', command: 'USER alice' },
          { label: 'Password', command: 'PASS s3cret' },
        ],
      },
      {
        name: 'Navigation',
        commands: [
          { label: 'Print working directory', command: 'PWD' },
          { label: 'Change directory', command: 'CWD pub' },
          { label: 'Parent directory', command: 'CDUP' },
          { label: 'List (long)', command: 'LIST' },
          { label: 'List names only', command: 'NLST' },
          { label: 'System type', command: 'SYST' },
        ],
      },
      {
        name: 'Transfer',
        commands: [
          { label: 'Passive mode', command: 'PASV', note: 'reply 227 (h1,h2,h3,h4,p1,p2)' },
          { label: 'Active mode', command: 'PORT 10,0,0,5,196,20', note: 'client listens; NAT-unfriendly' },
          { label: 'Binary transfer', command: 'TYPE I' },
          { label: 'ASCII transfer', command: 'TYPE A' },
          { label: 'Download', command: 'RETR backup.tar.gz' },
          { label: 'Upload', command: 'STOR upload.bin' },
          { label: 'Append', command: 'APPE log.txt' },
          { label: 'Restart download', command: 'REST 1024', note: 'then RETR' },
          { label: 'File size', command: 'SIZE backup.tar.gz' },
          { label: 'Modification time', command: 'MDTM backup.tar.gz' },
        ],
      },
      {
        name: 'Manage & finish',
        commands: [
          { label: 'Delete file', command: 'DELE old.txt' },
          { label: 'Make directory', command: 'MKD archive' },
          { label: 'Remove directory', command: 'RMD archive' },
          { label: 'Rename (step 1)', command: 'RNFR old.txt' },
          { label: 'Rename (step 2)', command: 'RNTO new.txt' },
          { label: 'Abort transfer', command: 'ABOR' },
          { label: 'Disconnect', command: 'QUIT' },
        ],
      },
    ],
  },
  {
    id: 'smtp',
    title: 'SMTP',
    protocol: 'SMTP',
    port: '25 / 587 / 465',
    summary:
      'Simple Mail Transfer Protocol. 25 is relay, 587 submission (STARTTLS), 465 implicit TLS. Every line ends with CRLF and the message body ends with a lone "." line.',
    groups: [
      {
        name: 'Connect & greet',
        commands: [
          { label: 'Connect', command: 'nc mail.example.com 25' },
          { label: 'Server greeting', command: '220 mail.example.com ESMTP', note: 'server → client' },
          { label: 'Extended hello', command: 'EHLO client.example.com' },
          { label: 'Basic hello', command: 'HELO client.example.com' },
          { label: 'Start TLS', command: 'STARTTLS', note: 'then re-issue EHLO' },
        ],
      },
      {
        name: 'Authenticate',
        commands: [
          { label: 'AUTH LOGIN', command: 'AUTH LOGIN', note: 'then send base64 user, then base64 pass' },
          { label: 'AUTH PLAIN', command: 'AUTH PLAIN AGFsaWNlAHMzY3JldA==', note: 'base64("\\0user\\0pass")' },
          { label: 'AUTH CRAM-MD5', command: 'AUTH CRAM-MD5', note: 'challenge/response' },
        ],
      },
      {
        name: 'Send a message',
        commands: [
          { label: 'Envelope sender', command: 'MAIL FROM:<alice@example.com>' },
          { label: 'Envelope recipient', command: 'RCPT TO:<bob@example.net>' },
          { label: 'Second recipient', command: 'RCPT TO:<carol@example.org>' },
          { label: 'Begin body', command: 'DATA', note: 'server replies 354, then type headers + body' },
          { label: 'From header', command: 'From: Alice <alice@example.com>' },
          { label: 'To header', command: 'To: Bob <bob@example.net>' },
          { label: 'Subject header', command: 'Subject: hello from netcat' },
          { label: 'Blank line', command: '', note: 'empty line separates headers from body' },
          { label: 'Body', command: 'This is a test message.' },
          { label: 'End of data', command: '.', note: 'a single dot on its own line' },
        ],
      },
      {
        name: 'Utilities & finish',
        commands: [
          { label: 'Reset transaction', command: 'RSET' },
          { label: 'Verify mailbox', command: 'VRFY alice' },
          { label: 'Expand list', command: 'EXPN staff' },
          { label: 'No-op / keepalive', command: 'NOOP' },
          { label: 'Disconnect', command: 'QUIT' },
        ],
      },
    ],
  },
  {
    id: 'pop3',
    title: 'POP3',
    protocol: 'POP3',
    port: '110 / 995',
    summary:
      'Post Office Protocol v3. Download-and-delete mailbox access; 995 is implicit TLS. Responses start with +OK or -ERR. CRLF line endings.',
    groups: [
      {
        name: 'Connect & authenticate',
        commands: [
          { label: 'Connect', command: 'nc pop.example.com 110' },
          { label: 'Server greeting', command: '+OK POP3 ready', note: 'server → client' },
          { label: 'User', command: 'USER alice' },
          { label: 'Password', command: 'PASS s3cret' },
          { label: 'APOP digest', command: 'APOP alice <digest>', note: 'MD5 of greeting timestamp + secret' },
          { label: 'Capabilities', command: 'CAPA' },
          { label: 'Start TLS', command: 'STLS', note: 'then re-authenticate' },
        ],
      },
      {
        name: 'Read',
        commands: [
          { label: 'Mailbox stats', command: 'STAT', note: '+OK count size' },
          { label: 'List messages', command: 'LIST' },
          { label: 'List one message', command: 'LIST 1' },
          { label: 'Unique ids', command: 'UIDL' },
          { label: 'Retrieve message', command: 'RETR 1' },
          { label: 'Headers + 5 lines', command: 'TOP 1 5' },
        ],
      },
      {
        name: 'Modify & finish',
        commands: [
          { label: 'Mark deleted', command: 'DELE 1', note: 'removed on QUIT' },
          { label: 'Undo deletes', command: 'RSET' },
          { label: 'No-op', command: 'NOOP' },
          { label: 'Commit & quit', command: 'QUIT', note: 'deletions become permanent' },
        ],
      },
    ],
  },
  {
    id: 'http',
    title: 'HTTP',
    protocol: 'HTTP',
    port: '80 / 443',
    summary:
      'Hypertext Transfer Protocol. Send a request line, Host header, then a blank line. CRLF ends each header. For 443 tick TLS in the toolbar and set the SNI.',
    groups: [
      {
        name: 'Basic requests',
        commands: [
          { label: 'Connect', command: 'nc example.com 80' },
          { label: 'GET request line', command: 'GET / HTTP/1.1' },
          { label: 'Host header', command: 'Host: example.com' },
          { label: 'End of headers', command: '', note: 'blank line; server then returns the body' },
          { label: 'HTTP/1.0 request', command: 'GET / HTTP/1.0', note: 'no Host required; closes after response' },
          { label: 'HEAD', command: 'HEAD / HTTP/1.1', note: 'headers only' },
          { label: 'OPTIONS', command: 'OPTIONS / HTTP/1.1' },
          { label: 'TRACE', command: 'TRACE / HTTP/1.1', note: 'often disabled' },
        ],
      },
      {
        name: 'POST a body',
        commands: [
          { label: 'Request line', command: 'POST /submit HTTP/1.1' },
          { label: 'Host header', command: 'Host: example.com' },
          { label: 'Content type', command: 'Content-Type: application/x-www-form-urlencoded' },
          { label: 'Content length', command: 'Content-Length: 23' },
          { label: 'Blank line', command: '' },
          { label: 'Body', command: 'name=alice&age=30' },
        ],
      },
      {
        name: 'Handy headers',
        commands: [
          { label: 'Close connection', command: 'Connection: close' },
          { label: 'User agent', command: 'User-Agent: netcat/1.0' },
          { label: 'Referer', command: 'Referer: https://example.com/' },
          { label: 'Cookie', command: 'Cookie: session=abc123' },
          { label: 'Authorization', command: 'Authorization: Basic YWxpY2U6czNjcmV0' },
          { label: 'Host override', command: 'Host: internal.example.com', note: 'virtual-host probing' },
        ],
      },
      {
        name: 'HTTPS',
        commands: [
          { label: 'TLS in this tool', command: 'nc example.com 443', note: 'enable the TLS checkbox; SNI = example.com' },
          { label: 'OpenSSL alternative', command: 'openssl s_client -connect example.com:443 -servername example.com' },
          { label: 'Send after handshake', command: 'GET / HTTP/1.1', note: 'then Host + blank line' },
        ],
      },
    ],
  },
  {
    id: 'imap',
    title: 'IMAP',
    protocol: 'IMAP',
    port: '143 / 993',
    summary:
      'Internet Message Access Protocol. Every command is prefixed with a unique tag (a1, a2, …); the server replies tagged OK/NO/BAD. 993 is implicit TLS. CRLF line endings.',
    groups: [
      {
        name: 'Connect & authenticate',
        commands: [
          { label: 'Connect', command: 'nc imap.example.com 143' },
          { label: 'Server greeting', command: '* OK IMAP4rev1 ready', note: 'server → client' },
          { label: 'Capabilities', command: 'a1 CAPABILITY' },
          { label: 'Login', command: 'a2 LOGIN alice s3cret' },
          { label: 'Start TLS', command: 'a3 STARTTLS', note: 'then re-issue CAPABILITY' },
          { label: 'Logout', command: 'a4 LOGOUT' },
        ],
      },
      {
        name: 'Browse',
        commands: [
          { label: 'List mailboxes', command: 'a5 LIST "" "*"' },
          { label: 'Select INBOX', command: 'a6 SELECT INBOX', note: 'read-write' },
          { label: 'Examine (read-only)', command: 'a7 EXAMINE INBOX' },
          { label: 'Mailbox status', command: 'a8 STATUS INBOX (MESSAGES UNSEEN RECENT)' },
          { label: 'Search unseen', command: 'a9 SEARCH UNSEEN' },
          { label: 'Search from', command: 'a10 SEARCH FROM "alice"' },
        ],
      },
      {
        name: 'Fetch & flag',
        commands: [
          { label: 'Fetch full message', command: 'a11 FETCH 1 BODY[]' },
          { label: 'Fetch headers', command: 'a12 FETCH 1 BODY[HEADER]' },
          { label: 'Fetch flags', command: 'a13 FETCH 1:* (FLAGS)' },
          { label: 'Fetch size', command: 'a14 FETCH 1 RFC822.SIZE' },
          { label: 'Mark seen', command: 'a15 STORE 1 +FLAGS (\\Seen)' },
          { label: 'Clear seen', command: 'a16 STORE 1 -FLAGS (\\Seen)' },
        ],
      },
      {
        name: 'Manage',
        commands: [
          { label: 'Create mailbox', command: 'a17 CREATE "Archive"' },
          { label: 'Delete mailbox', command: 'a18 DELETE "Archive"' },
          { label: 'Rename mailbox', command: 'a19 RENAME "Old" "New"' },
          { label: 'Copy message', command: 'a20 COPY 1 "Archive"' },
          { label: 'Expunge deleted', command: 'a21 EXPUNGE' },
          { label: 'Idle', command: 'a22 IDLE', note: 'server streams untagged updates' },
        ],
      },
    ],
  },
  {
    id: 'dns',
    title: 'DNS',
    protocol: 'DNS',
    port: '53 (TCP/UDP)',
    summary:
      'Domain Name System. DNS over TCP is binary and length-prefixed, so raw netcat queries are impractical — this sheet is a dig reference. This tool is TCP-only.',
    groups: [
      {
        name: 'Queries',
        commands: [
          { label: 'A record', command: 'dig +tcp @1.1.1.1 example.com A' },
          { label: 'AAAA record', command: 'dig +tcp @1.1.1.1 example.com AAAA' },
          { label: 'MX records', command: 'dig +tcp @1.1.1.1 example.com MX' },
          { label: 'NS records', command: 'dig +tcp @1.1.1.1 example.com NS' },
          { label: 'TXT records', command: 'dig +tcp @1.1.1.1 example.com TXT' },
          { label: 'SOA record', command: 'dig +tcp @1.1.1.1 example.com SOA' },
          { label: 'CAA record', command: 'dig +tcp @1.1.1.1 example.com CAA' },
          { label: 'ANY (often refused)', command: 'dig +tcp @1.1.1.1 example.com ANY' },
        ],
      },
      {
        name: 'Diagnostics',
        commands: [
          { label: 'Short answer only', command: 'dig +short example.com' },
          { label: 'Trace delegation', command: 'dig +trace example.com' },
          { label: 'Reverse lookup', command: 'dig +tcp @1.1.1.1 -x 8.8.8.8' },
          { label: 'No recursion', command: 'dig +tcp +norecurse @a.iana-servers.net example.com' },
          { label: 'Specify source port', command: 'dig +tcp -b 0.0.0.0 example.com' },
          { label: 'Zone transfer', command: 'dig +tcp @ns1.example.com example.com AXFR' },
        ],
      },
      {
        name: 'Raw TCP framing',
        commands: [
          { label: 'Connect', command: 'nc 1.1.1.1 53' },
          { label: 'Note', command: '', note: 'each DNS message is preceded by a 2-byte big-endian length' },
          { label: 'Hex dump a query', command: 'dig +tcp example.com | xxd' },
        ],
      },
    ],
  },
  {
    id: 'irc',
    title: 'IRC',
    protocol: 'IRC',
    port: '6667 / 6697',
    summary:
      'Internet Relay Chat. Plain text, CRLF lines, colon-prefixed trailing parameter. 6697 is implicit TLS. You must register a nickname before joining channels.',
    groups: [
      {
        name: 'Register',
        commands: [
          { label: 'Connect', command: 'nc irc.libera.chat 6667' },
          { label: 'Server notices', command: ':server 001 nick :Welcome', note: 'server → client' },
          { label: 'Server password', command: 'PASS s3cret', note: 'before NICK/USER if required' },
          { label: 'Nickname', command: 'NICK alice' },
          { label: 'User info', command: 'USER alice 0 * :Alice Example' },
          { label: 'Keepalive reply', command: 'PONG :token', note: 'reply to server PING' },
        ],
      },
      {
        name: 'Channels',
        commands: [
          { label: 'Join', command: 'JOIN #traceroute' },
          { label: 'Part', command: 'PART #traceroute :bye' },
          { label: 'Send to channel', command: 'PRIVMSG #traceroute :hello everyone' },
          { label: 'Send to user', command: 'PRIVMSG alice :hi there' },
          { label: 'Notice', command: 'NOTICE alice :heads up' },
          { label: 'Topic', command: 'TOPIC #traceroute' },
          { label: 'Names', command: 'NAMES #traceroute' },
          { label: 'Who', command: 'WHO #traceroute' },
          { label: 'Mode', command: 'MODE #traceroute +o alice' },
        ],
      },
      {
        name: 'Finish',
        commands: [
          { label: 'Quit', command: 'QUIT :leaving' },
          { label: 'List channels', command: 'LIST' },
          { label: 'Whois', command: 'WHOIS alice' },
          { label: 'Change nick', command: 'NICK bob' },
        ],
      },
    ],
  },
  {
    id: 'redis',
    title: 'Redis',
    protocol: 'RESP',
    port: '6379',
    summary:
      'Redis uses the RESP protocol. Inline commands (plain text, CRLF) work for simple cases; binary-safe clients use RESP arrays like *1\\r\\n$4\\r\\nPING\\r\\n.',
    groups: [
      {
        name: 'Connect & auth',
        commands: [
          { label: 'Connect', command: 'nc redis.example.com 6379' },
          { label: 'Ping', command: 'PING' },
          { label: 'Authenticate', command: 'AUTH s3cret' },
          { label: 'Select database', command: 'SELECT 0' },
          { label: 'Server info', command: 'INFO' },
          { label: 'Client list', command: 'CLIENT LIST' },
        ],
      },
      {
        name: 'Keys',
        commands: [
          { label: 'List keys', command: 'KEYS *' },
          { label: 'Set string', command: 'SET greeting "hello world"' },
          { label: 'Get string', command: 'GET greeting' },
          { label: 'Delete key', command: 'DEL greeting' },
          { label: 'Exists', command: 'EXISTS greeting' },
          { label: 'Type', command: 'TYPE greeting' },
          { label: 'TTL', command: 'TTL greeting' },
          { label: 'Expire', command: 'EXPIRE greeting 60' },
          { label: 'Database size', command: 'DBSIZE' },
          { label: 'Flush database', command: 'FLUSHDB', note: 'destructive' },
        ],
      },
      {
        name: 'Pub/Sub & admin',
        commands: [
          { label: 'Subscribe', command: 'SUBSCRIBE news' },
          { label: 'Publish', command: 'PUBLISH news "hello"' },
          { label: 'Monitor commands', command: 'MONITOR', note: 'live feed; noisy' },
          { label: 'Slow log', command: 'SLOWLOG GET 10' },
          { label: 'Config get', command: 'CONFIG GET maxmemory' },
          { label: 'Quit', command: 'QUIT' },
        ],
      },
      {
        name: 'RESP array form',
        commands: [
          { label: 'PING', command: '*1\\r\\n$4\\r\\nPING\\r\\n' },
          { label: 'GET key', command: '*2\\r\\n$3\\r\\nGET\\r\\n$3\\r\\nkey\\r\\n' },
        ],
      },
    ],
  },
  {
    id: 'mysql',
    title: 'MySQL',
    protocol: 'MySQL',
    port: '3306',
    summary:
      'The MySQL wire protocol is binary; netcat can only show the server handshake. Use the mysql client for queries — this sheet is a client reference.',
    groups: [
      {
        name: 'Handshake',
        commands: [
          { label: 'Connect', command: 'nc db.example.com 3306' },
          { label: 'Server greeting', command: 'binary handshake packet', note: 'includes version and auth plugin' },
          { label: 'Note', command: '', note: 'plain netcat cannot complete the binary auth exchange' },
        ],
      },
      {
        name: 'Client commands',
        commands: [
          { label: 'Connect as user', command: 'mysql -h db.example.com -P 3306 -u alice -p' },
          { label: 'Run one query', command: 'mysql -h db.example.com -u alice -p -e "SHOW DATABASES;"' },
          { label: 'Select database', command: 'mysql -h db.example.com -u alice -p appdb' },
          { label: 'No password prompt', command: 'mysql -h db.example.com -u alice --password=s3cret' },
          { label: 'SSL connection', command: 'mysql -h db.example.com -u alice -p --ssl-mode=REQUIRED' },
        ],
      },
      {
        name: 'Inside the shell',
        commands: [
          { label: 'Databases', command: 'SHOW DATABASES;' },
          { label: 'Tables', command: 'SHOW TABLES;' },
          { label: 'Describe table', command: 'DESCRIBE users;' },
          { label: 'Current user', command: 'SELECT USER(), CURRENT_USER();' },
          { label: 'Version', command: 'SELECT VERSION();' },
          { label: 'Server status', command: 'SHOW STATUS;' },
          { label: 'Quit', command: '\\q' },
        ],
      },
    ],
  },
  {
    id: 'whois',
    title: 'WHOIS',
    protocol: 'WHOIS',
    port: '43',
    summary:
      'WHOIS returns registration data for domains and IPs. You send a single query line and the server replies then closes. Use IANA to find the right registry.',
    groups: [
      {
        name: 'Domain queries',
        commands: [
          { label: 'Connect to IANA', command: 'nc whois.iana.org 43' },
          { label: 'Query a domain', command: 'example.com', note: 'reply contains a refer: server' },
          { label: 'Connect to registry', command: 'nc whois.verisign-grs.com 43' },
          { label: 'Exact-match query', command: 'domain example.com', note: 'COM/NET avoid substring matches' },
          { label: 'Thin registry note', command: '', note: 'then query the registrar for full details' },
        ],
      },
      {
        name: 'IP & ASN queries',
        commands: [
          { label: 'Connect to ARIN', command: 'nc whois.arin.net 43' },
          { label: 'Query an IP', command: 'n + 8.8.8.8' },
          { label: 'Query a network', command: 'n + 8.8.8.0/24' },
          { label: 'Query an ASN', command: 'a + AS15169' },
          { label: 'Abuse contact', command: 'n + 8.8.8.8' },
        ],
      },
      {
        name: 'CLI reference',
        commands: [
          { label: 'Domain', command: 'whois example.com' },
          { label: 'Specific server', command: 'whois -h whois.verisign-grs.com example.com' },
          { label: 'IP address', command: 'whois 8.8.8.8' },
          { label: 'ASN', command: 'whois AS15169' },
        ],
      },
    ],
  },
];

export function findCheatsheet(id: string | undefined): Cheatsheet | undefined {
  if (!id) {
    return undefined;
  }
  return CHEATSHEETS.find((sheet) => sheet.id === id);
}
