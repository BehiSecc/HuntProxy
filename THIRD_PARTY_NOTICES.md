# Third-Party Notices

HuntProxy release binaries contain the following embedded release assets. The
corresponding license and notice files are retained in the embedded archives and
in the source repositories identified below.

## Playwright Core 1.49.1

HuntProxy embeds the unmodified npm distribution archive for
`playwright-core@1.49.1`, verified against the package lock integrity value at
release preparation time.

- Project: [Microsoft Playwright](https://github.com/microsoft/playwright)
- Copyright: Microsoft Corporation
- License: Apache License 2.0
- Source version: `playwright-core` 1.49.1

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
