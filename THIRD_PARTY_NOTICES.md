# Third-Party Notices

HuntProxy release binaries contain the following embedded release assets and
trusted root certificate data. The
corresponding license and notice files are retained in the embedded archives and
in the source repositories identified below.

## Playwright Core 1.64.0

HuntProxy embeds the unmodified npm distribution archive for
`playwright-core@1.64.0`, verified against the package lock integrity value at
release preparation time.

- Project: [Microsoft Playwright](https://github.com/microsoft/playwright)
- Copyright: Microsoft Corporation
- License: Apache License 2.0
- Source version: `playwright-core` 1.64.0

Playwright includes code derived from the
[Puppeteer](https://github.com/puppeteer/puppeteer) project, also available
under the Apache License 2.0. The upstream Playwright `LICENSE` and `NOTICE`
files remain inside the embedded npm archive.

## HuntProxy First-Party Plugins

HuntProxy embeds the official plugin catalog from
[HuntProxy-Plugins](https://github.com/BehiSecc/HuntProxy-Plugins) at commit
`d4e1aa3f2907338d40361938deca8c4c711394e7`. The catalog also contains only
file fingerprints from the previously published trusted snapshot at commit
`95ad5b29cb02e8b1aa1c0ec0b6d7cb1e485f0c32`; source from that older snapshot
is not redistributed in the current catalog.

- Copyright: the HuntProxy-Plugins contributors
- License: Apache License 2.0
- Included provenance files: `LICENSE` and `THIRD_PARTY_NOTICES.md`

The plugin notice records the following additional provenance:

- ParamFinder redistributes word lists from PortSwigger Param Miner commit
  `4c35086a963cb68a608e91d90aef135be0f572a3`, licensed under Apache License
  2.0. The applicable upstream license text is retained with the relevant
  plugin resources.
- CacheAnalyzer contains a modified header list incorporating Param Miner
  entries and project-maintained additions, licensed under Apache License 2.0.
- Request Smuggler was reviewed against PortSwigger HTTP Request Smuggler
  commit `a25814d258c501b59b7f561d816f4d787c61ab70`; no source or resource file
  from that project is redistributed by the plugin.

The complete Apache License 2.0 terms are in [LICENSE](LICENSE).

## Trusted root certificates

The `webpki-roots` and `webpki-root-certs` Rust crates contain trusted root
certificate data used by HuntProxy and its HTTP dependencies.

- Project: [rustls/webpki-roots](https://github.com/rustls/webpki-roots)
- License: CDLA-Permissive-2.0

The following license text is reproduced from the `webpki-roots` distribution.

### Community Data License Agreement - Permissive - Version 2.0

This is the Community Data License Agreement - Permissive, Version
2.0 (the "agreement"). Data Provider(s) and Data Recipient(s) agree
as follows:

#### 1. Provision of the Data

1.1. A Data Recipient may use, modify, and share the Data made
available by Data Provider(s) under this agreement if that Data
Recipient follows the terms of this agreement.

1.2. This agreement does not impose any restriction on a Data
Recipient's use, modification, or sharing of any portions of the
Data that are in the public domain or that may be used, modified,
or shared under any other legal exception or limitation.

#### 2. Conditions for Sharing Data

2.1. A Data Recipient may share Data, with or without modifications, so
long as the Data Recipient makes available the text of this agreement
with the shared Data.

#### 3. No Restrictions on Results

3.1. This agreement does not impose any restriction or obligations
with respect to the use, modification, or sharing of Results.

#### 4. No Warranty; Limitation of Liability

4.1. All Data Recipients receive the Data subject to the following
terms:

THE DATA IS PROVIDED ON AN "AS IS" BASIS, WITHOUT REPRESENTATIONS,
WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED
INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE,
NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

NO DATA PROVIDER SHALL HAVE ANY LIABILITY FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING
WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE DATA OR RESULTS,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

#### 5. Definitions

5.1. "Data" means the material received by a Data Recipient under
this agreement.

5.2. "Data Provider" means any person who is the source of Data
provided under this agreement and in reliance on a Data Recipient's
agreement to its terms.

5.3. "Data Recipient" means any person who receives Data directly
or indirectly from a Data Provider and agrees to the terms of this
agreement.

5.4. "Results" means any outcome obtained by computational analysis
of Data, including for example machine learning models and models'
insights.
