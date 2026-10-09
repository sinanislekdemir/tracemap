# Third-Party Notices

Traceroute Map is licensed under the **MIT License** (see [`LICENSE`](LICENSE)).
It links and bundles the third-party components below; their own licenses apply
to those components. The full texts of the GNU licenses are in
[`LICENSES/`](LICENSES/).

## Qt 6 — LGPL-3.0-only

Traceroute Map uses [Qt 6](https://www.qt.io/) through the
[MIQT](https://github.com/mappu/miqt) Go bindings. Qt is Copyright (C) The Qt
Company and contributors and is used under the **GNU Lesser General Public
License, version 3** (LGPL-3.0-only), reproduced in
[`LICENSES/LGPL-3.0.txt`](LICENSES/LGPL-3.0.txt); that license incorporates the
GNU GPL v3, reproduced in [`LICENSES/GPL-3.0.txt`](LICENSES/GPL-3.0.txt).

- **Linux and macOS** builds link Qt **dynamically** against the system Qt.
  You are free to replace those Qt libraries, and the notice/license conditions
  above are met by shipping these texts.
- **Windows** builds link Qt **statically** (Qt 6.5.3, MinGW). LGPL-3.0 §4
  requires that you can relink the application against a modified Qt. To
  satisfy this, the complete corresponding application source (this repository,
  including the build scripts under `win/` and the `Makefile`) is available
  under the MIT License, and the corresponding Qt source is available from
  <https://build-qt.fsu0413.me/> and <https://download.qt.io/>.

To relink the Windows build against your own Qt build, use the container recipe
in `win/` (`win/build.sh`), which accepts any compatible statically linked Qt
6.5.3 tree. The Linux/macOS/AppImage builds are relinkable simply by rebuilding
from source with a different Qt. If you received a binary without the
corresponding source, it is available on request from
<sinan@islekdemir.com>.

Qt is a trademark of The Qt Company Ltd. and is used under the terms of the
LGPL; no endorsement by The Qt Company is implied.

## Go modules

Traceroute Map is written in Go and statically includes the following modules
(versions as pinned in [`go.mod`](go.mod)):

| Module | License |
| --- | --- |
| `github.com/mappu/miqt` | MIT |
| `github.com/oschwald/maxminddb-golang` | ISC |
| `golang.org/x/net` | BSD-3-Clause |
| `golang.org/x/sys` | BSD-3-Clause |
| `modernc.org/sqlite` | BSD-3-Clause |
| `modernc.org/libc` | BSD-3-Clause |
| `modernc.org/mathutil` | BSD-3-Clause |
| `modernc.org/memory` | BSD-3-Clause |
| `github.com/dustin/go-humanize` | MIT |
| `github.com/google/uuid` | BSD-3-Clause |
| `github.com/remyoudompheng/bigfft` | BSD-3-Clause |

The Go standard library is Copyright 2009 The Go Authors and is distributed
under a BSD-3-Clause license.

## License texts

### MIT License

Applies to `github.com/mappu/miqt` (Copyright 2024–2025, mappu; Copyright
2025, The MIQT developers) and `github.com/dustin/go-humanize` (Copyright (c)
2005–2008 Dustin Sallings <dustin@spy.net>).

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

### ISC License

Applies to `github.com/oschwald/maxminddb-golang` (Copyright (c) 2015, Gregory
J. Oschwald <oschwald@gmail.com>).

> Permission to use, copy, modify, and/or distribute this software for any
> purpose with or without fee is hereby granted, provided that the above
> copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
> REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
> AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
> INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
> LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
> OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
> PERFORMANCE OF THIS SOFTWARE.

### BSD 3-Clause License

Applies to `golang.org/x/net` and `golang.org/x/sys` (Copyright 2009 The Go
Authors), `github.com/google/uuid` (Copyright (c) 2009, 2014 Google Inc.),
`github.com/remyoudompheng/bigfft` (Copyright (c) 2012 The Go Authors), and the
`modernc.org/*` modules (Copyright (c) their respective authors, e.g. The
Sqlite / Libc / mathutil / Memory Authors).

> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice,
>    this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice,
>    this list of conditions and the following disclaimer in the documentation
>    and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors
>    may be used to endorse or promote products derived from this software
>    without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

## Bundled data

- **Basemap** — the embedded country/land geometry is derived from
  [Natural Earth](https://www.naturalearthdata.com/), which is in the **public
  domain**.
- **MaxMind GeoLite2** — the GeoLite2 database is **not bundled**. It is an
  optional, user-supplied file covered by MaxMind's End User License Agreement
  (<https://www.maxmind.com/en/geolite2/eula>). If you redistribute the
  database, include MaxMind's required attribution.
