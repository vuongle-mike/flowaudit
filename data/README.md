# ASVS catalogue provenance

`asvs-5.0.0.en.json` is an unmodified copy of the official OWASP ASVS 5.0.0 English JSON at the immutable release tag [v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0). The exact source URL, byte SHA-256, all 70 L1 requirement IDs and extraction rule are recorded in `asvs-provenance.json`. A second hash over `JSON.stringify` of the parsed catalogue verifies runtime integrity after TypeScript reformats copied build JSON; tests separately verify the original upstream bytes.

ASVS material is copyright OWASP ASVS contributors and licensed under [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/). The upstream license is reproduced in `ASVS-LICENSE.md`. These terms apply to the copied requirement text and adaptations of that text; they do not assign the upstream project's endorsement to this scanner.

The complete upstream JSON is retained for traceability. Only entries whose `L` equals `"1"` enter the L1 assessment checklist. L2 and L3 requirements are not relabeled as L1. Versioned IDs such as `v5.0.0-8.2.2` avoid mixing 4.x and 5.x numbering.

Scanner-specific review methods and evidence checklists are supplementary guidance. All 70 requirements begin `not-tested`. ZAP alert mappings only identify possibly relevant requirements; they do not automatically make a requirement pass or fail. The report must not claim ASVS certification or complete application coverage from these scans.

To refresh in a future release, choose an explicit official release tag, preserve its original JSON and license, update provenance/count/IDs, review every method and alert mapping, and run the catalogue and assessment tests. Do not silently refresh to the current upstream branch.
